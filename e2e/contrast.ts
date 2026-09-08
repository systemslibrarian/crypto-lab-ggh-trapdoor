import type { Page } from '@playwright/test';

/**
 * Composite-aware WCAG 1.4.3 contrast measurement, for THIS lab.
 *
 * This exists because axe is not a complete contrast oracle. Two classes of
 * text never reach the `violations` array a gate asserts on:
 *
 *  - TEXT OVER A SURFACE AXE DECLINES TO RESOLVE — a `color-mix()` over an
 *    unknown backdrop. Every surface that carries this lab's MEANING is one, in
 *    the fleet's house pattern `color-mix(in oklab, tone …%, var(--surface))`:
 *    the three verdict tones behind `#verdict-decrypt`, `#verdict-break1` and
 *    `#verdict-break2`, and any tint under the I1 proof and the I2 bound. Those
 *    fills hold the four sentences this lab exists to say — round-off with R
 *    recovered the message, round-off with B did not, Nguyen's mod-6 step
 *    recovered m from the public basis alone, and the fourth-moment descent
 *    recovered the rows of R. The shared top bar adds a `color-mix(in srgb, …)`
 *    for its ink. A violations-only gate measures the contrast of almost none of
 *    that.
 *
 *  - TEXT FADED BY AN ANCESTOR'S `opacity` — axe reads the declared `color`,
 *    which is not the colour that lands on screen. This page has two shapes at
 *    risk. A disabled control faded to `.5` is exempt as an inactive component
 *    and is skipped below for that reason — and this lab disables controls a
 *    lot: the Break 1 stepper at its last step, the run button during a descent,
 *    every downstream button before a key exists. The one that is NOT exempt is
 *    a matrix drawn dim to say "this is the long basis": the brief's visual
 *    semantics put the short basis in the accent and the long one in neutral,
 *    and "neutral" reached by fading a container is a 1.4.3 case the moment the
 *    faded thing is a number the reader is meant to read. §4.2 of the template
 *    says muted text must lower the colour's LIGHTNESS rather than use
 *    `opacity`, and this walk is what makes that a measurement rather than a
 *    rule nobody checks.
 *
 * So: walk every element that owns text, composite the real painted result
 * (translucent colours, gradient stops and opacity groups included), and
 * compute the ratio against the surface the text is genuinely sitting on
 * rather than against white. A gradient is judged at the text's own location.
 *
 * Opacity is modelled the way the compositor actually does it: an element with
 * `opacity < 1` renders its subtree into a group, then composites the group
 * over the backdrop. That means the *text* and the *background beside it* fade
 * onto the same backdrop independently — which is why both are carried through
 * the walk as a pair rather than fading the foreground alone.
 *
 * The ancestor walk is geometry-aware, because DOM ancestry is not the same
 * thing as "painted underneath". An absolutely positioned child can render
 * entirely outside its parent's box, and then the parent's background is simply
 * not behind it. So an ancestor's own paint is applied only when its border box
 * actually intersects the text's box; a partial intersection still counts, so
 * the judgement stays worst-case. Opacity is unconditional either way.
 *
 * Three things beyond that, each of which otherwise makes the helper report a
 * ratio nothing on screen has:
 *
 *  - TEXT SCROLLED OUT OF A CLIPPING ANCESTOR PAINTS NOTHING. This guard is
 *    LIVE here, not theoretical: a 60×60 integer basis does not reflow, so the
 *    matrix viewers are the one place this lab has to reach for
 *    `overflow-x: auto` — and at 380px it reaches for it early. Content
 *    scrolled past a clipper is not dimmed or partly drawn; it is absent from
 *    the frame, and asking what colour it sits on has no answer. Its rect falls
 *    outside every ancestor's box, so an unguarded walk finds nothing behind it,
 *    falls through to WHITE, and invents a failure for every matrix cell
 *    currently scrolled off. (`gate.ts`'s `expectScrollersReachable` is the
 *    other half of the same fact: a scroller here must be keyboard-operable.)
 *
 *  - TRANSPARENT TEXT PAINTS NOTHING. Anything drawn `color: transparent` lays
 *    no ink down; compositing a zero-alpha foreground returns the backdrop and
 *    reports a fixed 1:1.
 *
 *  - SVG PAINTS IN DOCUMENT ORDER, SO SIBLINGS CAN BE THE BACKGROUND. Unlike
 *    most of this fleet, that is a live concern here rather than a rule kept
 *    for later: this lab's headline visual is a 2-D projection of BOTH bases,
 *    an axis-and-vector diagram whose axes and lattice rules are the natural
 *    job for stroke-only `<line>` elements, and whose labelled basis vectors
 *    are the natural job for `<text>`. That is exactly the shape the `FILLED`
 *    guard below exists for: SVG's initial `fill` is black and
 *    `getComputedStyle` reports it for stroke-only geometry too, so an
 *    unguarded underlay walk treats every axis rule as an opaque black
 *    rectangle and reports a fabricated failure for the label that crosses it.
 *    Elsewhere in this fleet that invented a 3.82:1 for text whose real ratio
 *    was 6.15:1.
 *
 * TWO THINGS THIS WALK CANNOT SEE, stated so neither is mistaken for coverage.
 *
 * FIRST, generated content. The walk iterates ELEMENTS, and a
 * `::before`/`::after` is not one — nor is it one to axe's `color-contrast`
 * rule. `nontext.ts` covers that class separately, and here it has real work to
 * do: a styled `<select>` needs `appearance: none` and a custom chevron per
 * §4.2 of the template, and that chevron is a pseudo-element glyph.
 *
 * SECOND, `aria-hidden` text that is still painted — see the `ariaHidden` note
 * below. What that boundary hides on a page like this one is verdict glyphs
 * that sit beside their own words, and they are painted in semantic inks on the
 * `color-mix()` tints, so `gate.ts` measures every `aria-hidden` subtree
 * explicitly with that exemption lifted rather than reasoning about which
 * glyphs matter.
 *
 * AND ONE THING NOTHING HERE CAN SEE. `#break2-canvas` is a `<canvas>`: the
 * signature cloud is painted pixel by pixel, and neither this walk nor axe can
 * read a single one of them. That is why the selector contract at the top of
 * `a11y.spec.ts` requires the canvas to carry an accessible name AND a text
 * alternative saying what the picture shows — the text is the part any oracle
 * can judge, and the part a reader who cannot see the cloud actually gets.
 */

export interface ContrastFailure {
  selector: string;
  text: string;
  foreground: string;
  background: string;
  fontSize: number;
  fontWeight: number;
  required: number;
  ratio: number;
}

/**
 * `within` narrows the walk to one subtree; `includeAriaHidden` lifts the
 * accessibility-tree exemption for that walk.
 *
 * The default pair — whole page, `aria-hidden` skipped — matches axe's own
 * boundary and is what `scan()` uses for the page at large.
 *
 * The second form exists because of a real gap. SC 1.4.3 is about what a reader
 * SEES, and `aria-hidden` changes only what a reader HEARS, so painted text
 * inside an `aria-hidden` subtree still has to clear its ratio — yet axe skips
 * it and, by default, so does this walk. On this page the candidates are the
 * decorative glyph beside each verdict's words and any axis tick or basis label
 * inside the projection diagram that is marked decorative because the readout
 * beside it already says the number — all painted in semantic inks on
 * `color-mix()` tints, which is to say the states this lab exists to show. So
 * `scan()` calls this a second time as
 * `auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)`.
 */
export async function auditContrast(
  page: Page,
  within = 'body *',
  includeAriaHidden = false
): Promise<ContrastFailure[]> {
  return page.evaluate(([rootSelector, allowAriaHidden]: [string, boolean]) => {
    interface RGBA {
      r: number;
      g: number;
      b: number;
      a: number;
    }

    const TRANSPARENT: RGBA = { r: 0, g: 0, b: 0, a: 0 };
    const WHITE: RGBA = { r: 255, g: 255, b: 255, a: 1 };

    /**
     * Resolve ANY CSS colour to straight-alpha sRGB via a 1×1 canvas.
     *
     * A hand-rolled `rgba()` regex is not enough here: nearly every tinted
     * hero aside is authored with `color-mix()`, and Chromium reports that to
     * `getComputedStyle` unchanged rather than converting it to sRGB. A
     * regex that only understands `rgb()/rgba()` sees `null` for every one of
     * them and the walk then falls through to the wrong backdrop — which
     * fabricates failures (dark-on-light read as dark-on-dark) and, far worse,
     * could hide a real one. The 2D canvas is the browser's own colour
     * pipeline: assigning `fillStyle` converts any valid CSS colour — oklab,
     * color-mix, hwb, named, hex — to sRGB, and a painted pixel carries the
     * straight alpha back. Invalid input (a gradient direction keyword fed in by
     * mistake) is rejected by the two-sentinel check so it cannot masquerade as
     * black.
     */
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
    const colorCache = new Map<string, RGBA | null>();
    const resolve = (c: string): RGBA | null => {
      if (!c) return null;
      const cached = colorCache.get(c);
      if (cached !== undefined) return cached;
      let rgba: RGBA | null = null;
      // A valid colour normalises to the same value from either sentinel; an
      // invalid string leaves each sentinel in place and the two disagree.
      ctx.fillStyle = '#000';
      ctx.fillStyle = c;
      const fromBlack = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = c;
      const fromWhite = ctx.fillStyle;
      if (fromBlack === fromWhite) {
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = c;
        ctx.fillRect(0, 0, 1, 1);
        const d = ctx.getImageData(0, 0, 1, 1).data;
        rgba = { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
      }
      colorCache.set(c, rgba);
      return rgba;
    };

    /** Split on a separator char that sits at paren-nesting depth 0. */
    const splitTopLevel = (str: string, sep: string): string[] => {
      const out: string[] = [];
      let depth = 0;
      let cur = '';
      for (const ch of str) {
        if (ch === '(') depth++;
        else if (ch === ')') depth--;
        if (ch === sep && depth === 0) {
          out.push(cur);
          cur = '';
        } else {
          cur += ch;
        }
      }
      if (cur.trim()) out.push(cur);
      return out;
    };

    /** Standard source-over compositing of a (possibly translucent) src on dst. */
    const over = (src: RGBA, dst: RGBA): RGBA => {
      const a = src.a + dst.a * (1 - src.a);
      if (a === 0) return TRANSPARENT;
      return {
        r: (src.r * src.a + dst.r * dst.a * (1 - src.a)) / a,
        g: (src.g * src.a + dst.g * dst.a * (1 - src.a)) / a,
        b: (src.b * src.a + dst.b * dst.a * (1 - src.a)) / a,
        a,
      };
    };

    const fade = (c: RGBA, o: number): RGBA => (o >= 1 ? c : { ...c, a: c.a * o });

    const luminance = (c: RGBA): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };

    const ratio = (a: RGBA, b: RGBA): number => {
      const l1 = luminance(a);
      const l2 = luminance(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };

    interface Point {
      x: number;
      y: number;
    }
    interface Stop {
      color: RGBA;
      pos: number;
    }

    const clamp01 = (n: number): number => (n < 0 ? 0 : n > 1 ? 1 : n);

    /**
     * Interpolate a gradient's stop list at fraction `t`, in premultiplied
     * straight-alpha, the way the compositor blends a fade-to-`transparent`.
     */
    const colorAt = (stops: Stop[], t: number): RGBA => {
      if (!stops.length) return TRANSPARENT;
      if (t <= stops[0].pos) return stops[0].color;
      const last = stops[stops.length - 1];
      if (t >= last.pos) return last.color;
      let i = 0;
      while (i < stops.length - 1 && stops[i + 1].pos < t) i++;
      const a = stops[i];
      const b = stops[i + 1];
      const span = b.pos - a.pos;
      const f = span <= 0 ? 0 : (t - a.pos) / span;
      const al = a.color.a + (b.color.a - a.color.a) * f;
      const pr = a.color.r * a.color.a + (b.color.r * b.color.a - a.color.r * a.color.a) * f;
      const pg = a.color.g * a.color.a + (b.color.g * b.color.a - a.color.g * a.color.a) * f;
      const pb = a.color.b * a.color.a + (b.color.b * b.color.a - a.color.b * a.color.a) * f;
      return al === 0 ? TRANSPARENT : { r: pr / al, g: pg / al, b: pb / al, a: al };
    };

    /** Parse the colour-stop list of a gradient, normalising positions to 0..1. */
    const parseStops = (parts: string[]): Stop[] => {
      const raw: { color: RGBA; pos: number | null }[] = [];
      for (const part of parts) {
        const tokens = splitTopLevel(part.trim(), ' ').filter(Boolean);
        let color: RGBA | null = null;
        const positions: number[] = [];
        for (const tok of tokens) {
          const c = resolve(tok);
          if (c && !color) color = c;
          else if (tok.endsWith('%')) positions.push(parseFloat(tok) / 100);
        }
        if (!color) continue;
        // A stop may carry two positions (a hard band); emit one per position.
        if (positions.length === 0) raw.push({ color, pos: null });
        else for (const p of positions) raw.push({ color, pos: p });
      }
      if (!raw.length) return [];
      if (raw[0].pos === null) raw[0].pos = 0;
      if (raw[raw.length - 1].pos === null) raw[raw.length - 1].pos = 1;
      for (let i = 1; i < raw.length - 1; i++) {
        if (raw[i].pos !== null) continue;
        let j = i;
        while (j < raw.length && raw[j].pos === null) j++;
        const lo = raw[i - 1].pos as number;
        const hi = (raw[j]?.pos as number) ?? 1;
        for (let k = i; k < j; k++) raw[k].pos = lo + ((hi - lo) * (k - i + 1)) / (j - i + 1);
      }
      // CSS clamps positions to be non-decreasing.
      let run = 0;
      return raw.map((s) => {
        run = Math.max(run, s.pos as number);
        return { color: s.color, pos: run };
      });
    };

    const axisValue = (tok: string, origin: number, extent: number): number => {
      if (tok === 'left' || tok === 'top') return origin;
      if (tok === 'right' || tok === 'bottom') return origin + extent;
      if (tok === 'center') return origin + extent / 2;
      if (tok.endsWith('%')) return origin + (parseFloat(tok) / 100) * extent;
      if (tok.endsWith('px')) return origin + parseFloat(tok);
      return origin + extent / 2;
    };

    const VERT = new Set(['top', 'bottom']);
    const HORZ = new Set(['left', 'right']);

    /**
     * Evaluate one background-image layer at a document point.
     *
     * An earlier gate judged every gradient at its worst *stop*, assuming that
     * stop covered the text wherever the text sat. That is right only for a
     * gradient whose worst stop spans its element — elsewhere in this fleet a
     * `linear-gradient` running the full height of a several-screen document
     * put text near the top on a different surface than text near the bottom.
     * So each gradient is *sampled* at the text's real location instead:
     * linear by projecting onto the gradient line, radial by distance from the
     * centre over the farthest-corner radius. A non-gradient layer (`url()`,
     * `none`) is unmeasurable and paints nothing. Whether this lab's stylesheet
     * declares a gradient today is deliberately not asserted here — a wash
     * behind the basis-projection panel or the signature cloud is one commit
     * away, and this page runs five acts deep, which is precisely the geometry
     * where a full-height gradient puts the Act 1 matrices on a different
     * surface from the Act 5 comparison. It is the fleet's paint model and
     * stays whole: the first `linear-gradient` is measured on arrival rather
     * than silently misread.
     */
    const sampleLayer = (layer: string, rect: DOMRect, p: Point): RGBA => {
      if (!/gradient/.test(layer)) return TRANSPARENT;
      const inner = layer.slice(layer.indexOf('(') + 1, layer.lastIndexOf(')'));
      const parts = splitTopLevel(inner, ',').map((s) => s.trim());
      const radial = /radial-gradient/.test(layer);
      // The first part is configuration (angle / shape / position) exactly when
      // it holds no resolvable colour.
      const firstColour = parts[0]
        ? splitTopLevel(parts[0], ' ').some((t) => resolve(t.trim()))
        : false;
      const config = firstColour ? '' : parts[0] ?? '';
      const stops = parseStops(firstColour ? parts : parts.slice(1));
      if (!stops.length) return TRANSPARENT;

      if (radial) {
        // Centre: `... at X Y`. Default centre of the box.
        let cx = rect.left + rect.width / 2;
        let cy = rect.top + rect.height / 2;
        const at = config.split(/\s+at\s+/)[1];
        if (at) {
          const toks = at.split(/\s+/).filter(Boolean);
          const kw = toks.filter((t) => VERT.has(t) || HORZ.has(t) || t === 'center');
          const vals = toks.filter((t) => !kw.includes(t));
          for (const t of toks) {
            if (HORZ.has(t)) cx = axisValue(t, rect.left, rect.width);
            else if (VERT.has(t)) cy = axisValue(t, rect.top, rect.height);
          }
          if (vals[0]) cx = axisValue(vals[0], rect.left, rect.width);
          if (vals[1]) cy = axisValue(vals[1], rect.top, rect.height);
        }
        // Default ending shape is farthest-corner.
        const corners = [
          [rect.left, rect.top],
          [rect.right, rect.top],
          [rect.left, rect.bottom],
          [rect.right, rect.bottom],
        ];
        const radius = Math.max(...corners.map(([x, y]) => Math.hypot(x - cx, y - cy)));
        const t = radius <= 0 ? 0 : Math.hypot(p.x - cx, p.y - cy) / radius;
        return colorAt(stops, clamp01(t));
      }

      // Linear. Default direction is `to bottom` (180deg).
      let angle = 180;
      if (/deg/.test(config)) angle = parseFloat(config);
      else if (/to\s+top/.test(config)) angle = 0;
      else if (/to\s+right/.test(config)) angle = 90;
      else if (/to\s+left/.test(config)) angle = 270;
      const rad = (angle * Math.PI) / 180;
      const dir = { x: Math.sin(rad), y: -Math.cos(rad) };
      const len = Math.abs(rect.width * Math.sin(rad)) + Math.abs(rect.height * Math.cos(rad));
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const d = (p.x - cx) * dir.x + (p.y - cy) * dir.y;
      const t = len <= 0 ? 0.5 : 0.5 + d / len;
      return colorAt(stops, clamp01(t));
    };

    /**
     * The colour this element's own box paints at the text point: its
     * background-color with every background-image layer sampled and composited
     * in paint order (first-listed layer on top).
     */
    const paintAt = (cs: CSSStyleDeclaration, rect: DOMRect, p: Point): RGBA => {
      let result = resolve(cs.backgroundColor) ?? TRANSPARENT;
      const bi = cs.backgroundImage;
      if (!bi || bi === 'none') return result;
      const layers = splitTopLevel(bi, ',').map((s) => s.trim());
      // Composite bottom (last-listed) up to top (first-listed).
      for (let i = layers.length - 1; i >= 0; i--) {
        result = over(sampleLayer(layers[i], rect, p), result);
      }
      return result;
    };

    /** Do two border boxes share any painted area at all? */
    const intersects = (a: DOMRect, b: DOMRect): boolean =>
      Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) > 0 &&
      Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top)) > 0;

    /** Does `a` sit entirely inside `b`? */
    const contains = (outer: DOMRect, inner: DOMRect): boolean =>
      inner.left >= outer.left - 0.5 &&
      inner.right <= outer.right + 0.5 &&
      inner.top >= outer.top - 0.5 &&
      inner.bottom <= outer.bottom + 0.5;

    /**
     * Style and geometry are memoised per element for one pass.
     *
     * A driven pass here walks all five acts at once — this lab is a scrolled
     * page, not a tablist, so every act is in the DOM at every scan — and the
     * expensive part is the matrices. The basis-pair viewer shows R and B side
     * by side, which at dimension 60 is 7,200 integer cells; the U·V = I proof
     * adds another grid, the ciphertext strip one row per coordinate with every
     * entry of e called out, and the Break 1 stepper its residual vectors. They
     * are all siblings re-walking the same ancestors up to `<body>`, so without
     * the caches the pass re-reads the same computed styles and rects tens of
     * thousands of times. Nothing mutates the DOM during the pass, so the
     * cached values cannot go stale.
     */
    const styleCache = new Map<Element, CSSStyleDeclaration>();
    const styleOf = (el: Element): CSSStyleDeclaration => {
      let cs = styleCache.get(el);
      if (!cs) {
        cs = getComputedStyle(el);
        styleCache.set(el, cs);
      }
      return cs;
    };
    const rectCache = new Map<Element, DOMRect>();
    const rectOf = (el: Element): DOMRect => {
      let r = rectCache.get(el);
      if (!r) {
        r = el.getBoundingClientRect();
        rectCache.set(el, r);
      }
      return r;
    };

    /**
     * Every container that clips its overflow, with the box it clips to.
     *
     * An `overflow: auto` container paints only what falls inside that box.
     * Content scrolled beyond it is not dimmed or partly drawn — it is absent
     * from the frame, and asking what colour it sits on has no answer. This lab
     * genuinely needs scrollers: a 60×60 integer basis is a GRID and cannot
     * reflow the way a paragraph can, so the matrix viewers are horizontal
     * scroll regions and at
     * 380px most of every row is outside the clip box. The collection is built
     * from the live DOM at each scan, so a scroller that only exists at one
     * viewport width is still found at that width.
     */
    const clippers = Array.from(document.querySelectorAll('body *')).filter((el) => {
      const cs = styleOf(el);
      return /auto|scroll|hidden|clip/.test(cs.overflowX + ' ' + cs.overflowY);
    });

    const clippedAway = (el: Element, box: DOMRect): boolean =>
      clippers.some((c) => c !== el && c.contains(el) && !intersects(box, rectOf(c)));

    /**
     * SVG has no `background-color`: shapes paint in document order, so the
     * surface under a `<text>` is whichever earlier sibling shape lies beneath
     * it. Composite those, innermost-last, before the ancestor walk starts.
     */
    const svgUnderlay = (el: Element, box: DOMRect): RGBA => {
      let bg = TRANSPARENT;
      let sib = el.previousElementSibling;
      const stack: Element[] = [];
      while (sib) {
        stack.push(sib);
        sib = sib.previousElementSibling;
      }
      // Earliest sibling first — that is the order the compositor paints in.
      // Only shapes that actually PAINT A FILL can be a backdrop. SVG's initial
      // `fill` is black, and `getComputedStyle` reports that for stroke-only
      // geometry too — so a <line> used as a grid rule or axis reads as an
      // opaque black rectangle covering whatever it crosses. Compositing that
      // invented a 3.82:1 failure elsewhere in this fleet for labels whose real
      // ratio was 6.15:1. This lab is the case that rule was written for: its
      // headline visual is a 2-D projection of the two bases, so the moment
      // that diagram gains axes, lattice rules or a drawn parallelepiped edge
      // as stroke-only <line>s — and it will, that is what the picture is —
      // every basis-vector label crossing one of them would be judged against
      // an opaque black rectangle that is not on screen.
      const FILLED = ['rect', 'circle', 'ellipse', 'polygon', 'path'];
      for (const s of stack.reverse()) {
        if (!FILLED.includes(s.tagName.toLowerCase())) continue;
        if (!contains(rectOf(s), box)) continue;
        const scs = styleOf(s);
        const fill = resolve(scs.fill);
        if (!fill) continue;
        const op = parseFloat(scs.fillOpacity || '1') * parseFloat(scs.opacity || '1');
        bg = over(fade(fill, Number.isFinite(op) ? op : 1), bg);
      }
      return bg;
    };

    /**
     * Does this element's own `clip` / `clip-path` reduce it to zero area?
     *
     * `clip: rect(t, r, b, l)` applies only to absolutely positioned boxes and
     * is what the classic `.sr-only` recipe uses; `clip-path: inset(50%)` is
     * the modern spelling of the same trick. Either one at zero area means the
     * compositor draws nothing, so there is no painted ink to measure.
     */
    const clippedToNothing = (cs: CSSStyleDeclaration): boolean => {
      const clip = cs.clip;
      if (clip && clip !== 'auto') {
        const nums = clip.match(/-?[\d.]+/g)?.map(Number);
        if (nums && nums.length === 4) {
          // Tuple-typed: under `noUncheckedIndexedAccess` a plain destructure of
          // `number[]` yields `number | undefined` for each name, which fails
          // `tsc --noEmit` in the repos whose build typechecks the e2e tree.
          const [top, right, bottom, left] = nums as [number, number, number, number];
          if (bottom - top <= 0 || right - left <= 0) return true;
        }
      }
      // `inset(50%)` (and anything >= 50% on both axes) collapses to nothing.
      const path = cs.clipPath;
      if (path && path.startsWith('inset(')) {
        const pct = path.match(/([\d.]+)%/g)?.map((v) => parseFloat(v)) ?? [];
        if (pct.length && pct.every((v) => v >= 50)) return true;
      }
      return false;
    };

    const isVisible = (el: Element): boolean => {
      const cs = styleOf(el);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (parseFloat(cs.opacity) === 0) return false;
      // A closed <details> hides its body with `content-visibility: hidden`,
      // not `display: none`, and Chromium keeps the last laid-out geometry for
      // that subtree — so the `display`/rect tests above all pass for text
      // that paints nothing. `checkVisibility()` catches it. This lab's natural
      // home for the shape is depth-on-demand: the HNF public-key variant, the
      // full U matrix, the per-coordinate round-off arithmetic — the material
      // the brief keeps behind an "extension seam" rather than in the reader's
      // face. Wherever a <details> ships shut, the gate opens it by clicking its
      // <summary>, which is the route a reader has, rather than setting `.open`
      // from script — which is what the gate this replaces did, to every
      // <details> on the page, before its only scan.
      if ((el as HTMLElement).checkVisibility?.() === false) return false;
      const r = rectOf(el);
      if (r.width <= 0 || r.height <= 0) return false;
      // Text parked off the left/top edge of the page paints no pixels. This is
      // the WCAG-sanctioned "visually hidden until focused" idiom: the shared
      // header's `.cl-skip-link` — the page's only one — parks at `top:-3rem`
      // and slides in only on focus. Measuring the parked copy invents a failure
      // for text that is not on screen; the focused rendering is a real state
      // and the gate scans it explicitly instead.
      // Document space, NOT viewport space. `getBoundingClientRect()` is
      // relative to the viewport, so after Playwright scrolls a control into
      // view every element ABOVE the viewport has `bottom <= 0` and this guard
      // silently dropped it from the walk. On a page taller than the viewport
      // that is most of the document, and it is why a green contrast run on a
      // long page could not be trusted. Adding the scroll offset restores the
      // original intent — text parked off the top/left of the DOCUMENT, the
      // "visually hidden until focused" idiom — without hiding the page.
      if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
      // Scrolled out of an `overflow: auto` container — clipped, not painted.
      if (clippedAway(el, r)) return false;
      // Clipped to nothing by the element's own `clip` / `clip-path`. This is
      // the OTHER WCAG-sanctioned visually-hidden idiom: `position: absolute;
      // width: 1px; height: 1px; clip: rect(0 0 0 0)` paints nothing at all —
      // the box has a rect and passes `checkVisibility()`, but the compositor
      // draws zero pixels of it — and its modern spelling `clip-path:
      // inset(50%)` does the same. Measuring either reports a ratio for ink
      // that was never laid down.
      //
      // This lab does NOT use the idiom today: it has no `.sr-only` class, and
      // every `role="status"` live region here — the message byte count, the
      // tamper output, the equation stage, the vectors summary — is a VISIBLE
      // element whose ink this walk measures for real. The guard stays because
      // the day a visually-hidden announcer is added (the normal next step for
      // a lab like this), measuring it would report a fresh phantom ratio on
      // every scan. It is deliberately narrow: only a ZERO-AREA clip
      // qualifies, so a partially clipped element is still measured, worst
      // case.
      if (clippedToNothing(cs)) return false;
      return true;
    };

    const ownText = (el: Element): string => {
      let t = '';
      for (const n of Array.from(el.childNodes)) {
        if (n.nodeType === Node.TEXT_NODE) t += n.textContent ?? '';
      }
      return t.trim();
    };

    const describe = (el: Element): string => {
      let s = el.tagName.toLowerCase();
      if (el.id) s += `#${el.id}`;
      const cls = el.getAttribute('class');
      if (cls) s += `.${cls.trim().split(/\s+/).join('.')}`;
      return s;
    };

    /**
     * WCAG 1.4.3 exempts text that is part of an *inactive* user-interface
     * component, and axe skips disabled controls for the same reason. Honour
     * that here so a deliberately dimmed disabled control is not reported as a
     * failure the spec does not actually require fixing.
     */
    const inactive = (el: Element): boolean => {
      let n: Element | null = el;
      while (n) {
        if ((n as HTMLInputElement).disabled === true) return true;
        if (n.getAttribute('aria-disabled') === 'true') return true;
        n = n.parentElement;
      }
      return false;
    };

    /**
     * `aria-hidden` text is removed from the accessibility tree, so axe's own
     * `color-contrast` rule skips it — and this arithmetic oracle exists to
     * catch what axe *misses* among exposed text (gradients, opacity), not to be
     * stricter than axe on decorative content. Honour the same boundary.
     *
     * The boundary cuts both ways and is a known gap: text that is
     * `aria-hidden` but still painted is skipped by BOTH oracles. That is the
     * one place a live readout can hide from an entire accessibility gate, so
     * it is closed by MEASUREMENT rather than by an inventory — see
     * `includeAriaHidden` and the `[aria-hidden="true"]` call in `gate.ts`'s
     * `scan()`, which runs this whole walk a second time over every
     * `aria-hidden` subtree with the exemption lifted, at every driven state.
     *
     * That second pass is deliberately not backed by a written list of what
     * this page hides, and the reason is worth stating: this gate was written
     * before the lab's markup existed, so any list here would be a guess, and a
     * guessed inventory is exactly the kind of prose that reads as verification
     * without being any. The shapes to expect are the decorative glyph beside
     * each verdict's words and the tick labels or vector marks inside the
     * basis-projection diagram — but the check does not depend on that being
     * right, which is the point.
     *
     * What DOES need a human eye, and what no oracle can settle, is the
     * question `aria-hidden` actually asks: is the thing hidden a duplicate of
     * words already beside it, or is it the only place a value appears? On this
     * page the values that must never be hidden are the I1 proof, the I2 bound,
     * the signature counter and the three verdicts — a matrix entry or a cloud
     * point may be decorative, but a number the lab asks the reader to believe
     * never is.
     */
    const ariaHidden = (el: Element): boolean => {
      if (allowAriaHidden) return false;
      let n: Element | null = el;
      while (n) {
        if (n.getAttribute('aria-hidden') === 'true') return true;
        n = n.parentElement;
      }
      return false;
    };

    /**
     * SVG renders character data only inside `<text>` / `<tspan>`. Text sitting
     * directly in a `<g>`, `<svg>` or shape element is in the DOM but paints
     * nothing, so it has no colour and no contrast requirement.
     *
     * A lab that draws a basis diagram builds it from template literals, and
     * that is exactly how this mistake arrives: interpolating a string ARRAY
     * into a literal makes JS join it with commas, leaving a run of "," text
     * nodes inside whatever element wraps it. A row of a matrix is a string
     * array; so is a list of `<line>` markup for the lattice rules. Inside a
     * `<g>` those commas render nothing, while a walk that measured them would
     * report a 1:1 failure describing ink that was never laid down.
     */
    const SVG_NS = 'http://www.w3.org/2000/svg';
    const nonRenderingSvgText = (el: Element): boolean =>
      el.namespaceURI === SVG_NS && !['text', 'tspan'].includes(el.tagName.toLowerCase());

    /**
     * The CANVAS background — what is painted behind everything.
     *
     * The ancestor walk is geometry-aware, which is right for ordinary boxes: a
     * parent whose border box does not overlap the text paints nothing behind
     * it. Applied to the ROOT it is wrong, and wrong in the direction that
     * FABRICATES failures. CSS propagates the root element's background to the
     * canvas and paints it over the whole canvas regardless of the root's own
     * box (CSS Backgrounds 3, "The Canvas Background"); if the root's own
     * background is transparent the value is taken from `<body>` instead.
     *
     * The failure this prevents is not hypothetical — it cost a run elsewhere in
     * this fleet. A lab that sets `html, body { height: 100% }` has both boxes
     * exactly one viewport tall while the document runs several viewports long,
     * so every element below the fold intersects neither, the walk ends with a
     * transparent backdrop, and it falls through to WHITE. In a dark theme that
     * reports muted footer text against a white page that does not exist — 34 of
     * 38 findings in one run elsewhere in this fleet — and it can mask a real
     * failure in the other direction just as easily.
     *
     * Whether it is a no-op here depends on declarations that are easy to
     * change and easy to miss, which is the argument for keeping it: this page
     * runs five acts and many screens deep — two full bases, a ciphertext
     * strip, a stepper and a signature cloud — so the day a `height: 100%`
     * appears on `html` or `body`, everything below the first screen would
     * report against a white page that does not exist, in a lab whose only
     * canvas is near-black. Act 1 alone is taller than a viewport at any
     * dimension worth showing.
     */
    const canvasBackground = ((): RGBA => {
      const rootCs = styleOf(document.documentElement);
      const rootRect = rectOf(document.documentElement);
      const rootPaint = paintAt(rootCs, rootRect, {
        x: rootRect.left + rootRect.width / 2,
        y: rootRect.top + rootRect.height / 2,
      });
      if (rootPaint.a > 0) return rootPaint;
      const body = document.body;
      if (!body) return TRANSPARENT;
      const bodyRect = rectOf(body);
      return paintAt(styleOf(body), bodyRect, {
        x: bodyRect.left + bodyRect.width / 2,
        y: bodyRect.top + bodyRect.height / 2,
      });
    })();

    const failures: unknown[] = [];
    for (const el of Array.from(document.querySelectorAll(rootSelector))) {
      const text = ownText(el);
      if (!text) continue;
      if (!isVisible(el)) continue;
      if (inactive(el)) continue;
      if (ariaHidden(el)) continue;
      if (nonRenderingSvgText(el)) continue;

      const cs = styleOf(el);
      // SVG text takes its ink from `fill`, not `color`. Reading `color` on an
      // SVG <text>
      // measures an inherited value the glyphs are not painted in.
      const svgText = el.namespaceURI === 'http://www.w3.org/2000/svg';
      const fgRaw = resolve(svgText ? cs.fill : cs.color);
      if (!fgRaw) continue;
      // `color: transparent` lays no ink down at all; compositing a zero-alpha
      // foreground just returns the backdrop and reports a fixed 1:1.
      if (fgRaw.a === 0) continue;

      const size = parseFloat(cs.fontSize);
      const weight = parseInt(cs.fontWeight, 10) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const required = large ? 3 : 4.5;

      // Carry (text, adjacent background) as a pair up the ancestor chain,
      // sampling each ancestor's own background at the text point beneath both
      // and applying that ancestor's opacity to both, exactly as the compositor
      // would. The point is the text box centre.
      const textBox = rectOf(el);
      const point: Point = {
        x: (textBox.left + textBox.right) / 2,
        y: (textBox.top + textBox.bottom) / 2,
      };
      // For SVG text the first thing beneath the glyphs is a sibling shape, not
      // an ancestor's background — see the header note on the SVG figures.
      let fg = fgRaw;
      let bg = svgText ? svgUnderlay(el, textBox) : TRANSPARENT;
      let node: Element | null = el;
      while (node) {
        const ncs = styleOf(node);
        const opacity = parseFloat(ncs.opacity);
        // An ancestor that does not overlap the text paints nothing behind it.
        const paint =
          node === el || intersects(textBox, rectOf(node))
            ? paintAt(ncs, rectOf(node), point)
            : TRANSPARENT;
        fg = fade(over(fg, paint), opacity);
        bg = fade(over(bg, paint), opacity);
        // Stop once the accumulated backdrop is fully opaque: nothing further
        // out can change the painted result.
        if (bg.a >= 1) break;
        node = node.parentElement;
      }

      const fgFinal = over(over(fg, canvasBackground), WHITE);
      const bgFinal = over(over(bg, canvasBackground), WHITE);
      const worst = { r: ratio(fgFinal, bgFinal), fg: fgFinal, bg: bgFinal };

      // Round to 2dp before comparing so a value that is exactly on the floor
      // (e.g. 4.50) is not failed by float noise, and one just under it is not
      // rounded up into a pass.
      const rounded = Math.round(worst.r * 100) / 100;
      if (rounded >= required) continue;

      const show = (c: RGBA): string =>
        `rgb(${[c.r, c.g, c.b].map((v) => Math.round(v)).join(', ')})`;

      failures.push({
        selector: describe(el),
        text: text.slice(0, 60),
        foreground: show(worst.fg),
        background: show(worst.bg),
        fontSize: size,
        fontWeight: weight,
        required,
        ratio: rounded,
      });
    }
    return failures as never;
  }, [within, includeAriaHidden] as [string, boolean]);
}

/** Render failures as short strings so an assertion diff is readable. */
export function formatContrastFailures(failures: ContrastFailure[]): string[] {
  return failures.map(
    (f) =>
      `${f.ratio}:1 (needs ${f.required}:1) ${f.selector} — fg ${f.foreground} on ${f.background} — "${f.text}"`
  );
}
