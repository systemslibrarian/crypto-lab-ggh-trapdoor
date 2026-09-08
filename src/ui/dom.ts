/**
 * Small DOM helpers.
 *
 * The verdict helper is the one that matters: WCAG 1.4.1 forbids conveying state
 * by colour alone, so every verdict this lab renders carries an icon, a word,
 * and a colour together. The colour tracks SYSTEM INTEGRITY rather than the raw
 * return value -- a forged signature that the real verifier accepts is an
 * "alarm" verdict, not a green success, because the system is broken even though
 * the function returned true.
 */

export type VerdictKind = 'ok' | 'bad' | 'warn' | 'idle';

/** Find an element by id or throw -- a missing id is a build error, not a runtime branch. */
export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
}

const ICONS: Record<VerdictKind, string> = {
  ok: 'OK',
  bad: '!!',
  warn: '/!\\',
  idle: '--',
};

/**
 * The machine-readable outcome, mirrored onto the verdict container as
 * `data-verdict` so tests can assert the OUTCOME without depending on wording.
 *
 * TWO AXES, ON PURPOSE, AND THEY DO NOT ALWAYS AGREE:
 *
 *   `data-verdict` describes THE OPERATION the panel demonstrates. Round-off
 *   with the private basis is 'pass'; with the public basis it is 'fail'; an
 *   attack that recovers the secret is 'alarm'; an attack that does not is
 *   'fail'.
 *
 *   The COLOUR describes SYSTEM INTEGRITY, which is what the template requires
 *   of colour. So a failed attack is a 'fail' operation painted GREEN -- the
 *   attack did not work, which is good news about the system.
 *
 * The two axes are kept separate rather than collapsed because collapsing them
 * breaks immediately: decryption failing with the public basis is the scheme
 * working exactly as designed, so under a system-integrity reading it would have
 * to be 'pass', and a test could no longer tell it from a decryption that
 * wrongly succeeded.
 *
 * 'alarm' is never a synonym for 'fail'. It means the system is broken while
 * every check it performs reports success -- a forgery the real verifier
 * accepted. An attack that works is an alarm, never a green pass.
 */
export type VerdictState = 'pass' | 'fail' | 'alarm' | 'idle';

/**
 * Render a verdict block.
 *
 * `label` is the short word screen readers and colour-blind users rely on;
 * `detail` carries the numbers. Both are always present.
 *
 * `state` sets `data-verdict` on the container. When omitted it is derived from
 * `kind`, which is right for the ordinary pass/fail panels; the two break panels
 * pass 'alarm' explicitly.
 */
export function verdict(
  target: HTMLElement,
  kind: VerdictKind,
  label: string,
  detail: string,
  state?: VerdictState,
): void {
  target.innerHTML = '';
  const resolved: VerdictState =
    state ?? (kind === 'ok' ? 'pass' : kind === 'idle' ? 'idle' : 'fail');
  target.dataset.verdict = resolved;
  const box = document.createElement('div');
  box.className = `verdict verdict-${kind}`;
  const icon = document.createElement('span');
  icon.className = 'verdict-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = ICONS[kind];
  const body = document.createElement('div');
  const strong = document.createElement('span');
  strong.className = 'verdict-label';
  strong.textContent = label;
  body.appendChild(strong);
  const p = document.createElement('span');
  p.textContent = ` ${detail}`;
  body.appendChild(p);
  box.appendChild(icon);
  box.appendChild(body);
  target.appendChild(box);
}

/**
 * Empty a readout and mark it retired.
 *
 * Retirement is a correctness rule, not housekeeping: once the key or the error
 * mode changes, every verdict on the page was computed from inputs that no
 * longer exist. Leaving a stale PASS on screen would be the page lying about
 * what it just did.
 */
export function retire(...targets: HTMLElement[]): void {
  for (const t of targets) {
    t.innerHTML = '';
    t.dataset.verdict = 'idle';
  }
}

/** A definition list of computed values. `tone` colours the value, never alone. */
export function kvList(
  target: HTMLElement,
  rows: Array<{ k: string; v: string; tone?: 'good' | 'bad' }>,
): void {
  target.innerHTML = '';
  const dl = document.createElement('dl');
  dl.className = 'kv';
  for (const row of rows) {
    const wrap = document.createElement('div');
    const dt = document.createElement('dt');
    dt.textContent = row.k;
    const dd = document.createElement('dd');
    dd.textContent = row.v;
    if (row.tone) dd.classList.add(row.tone);
    wrap.appendChild(dt);
    wrap.appendChild(dd);
    dl.appendChild(wrap);
  }
  target.appendChild(dl);
}

/** Fixed-width number, so columns of readouts line up and do not jitter. */
export function fx(x: number, digits = 4): string {
  if (!Number.isFinite(x)) return x > 0 ? 'inf' : '-inf';
  return x.toFixed(digits);
}

/** Render a matrix as a scrollable table. Scroll regions need a role and a name. */
export function matrixTable(
  target: HTMLElement,
  M: Float64Array[],
  label: string,
  maxRows = 12,
  maxCols = 12,
): void {
  target.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'matrix-scroll';
  wrap.tabIndex = 0;
  wrap.setAttribute('role', 'region');
  wrap.setAttribute('aria-label', label);
  const table = document.createElement('table');
  const rows = Math.min(M.length, maxRows);
  const cols = Math.min(M[0].length, maxCols);
  for (let i = 0; i < rows; i++) {
    const tr = document.createElement('tr');
    for (let j = 0; j < cols; j++) {
      const td = document.createElement('td');
      td.textContent = String(M[i][j]);
      if (i === j) td.className = 'diag';
      tr.appendChild(td);
    }
    if (cols < M[0].length) {
      const td = document.createElement('td');
      td.textContent = '...';
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }
  if (rows < M.length) {
    const tr = document.createElement('tr');
    for (let j = 0; j < cols + (cols < M[0].length ? 1 : 0); j++) {
      const td = document.createElement('td');
      td.textContent = '...';
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }
  wrap.appendChild(table);
  target.appendChild(wrap);
  const cap = document.createElement('p');
  cap.className = 'panel-hint';
  cap.textContent = `${label} - showing ${rows}x${cols} of ${M.length}x${M[0].length}.`;
  target.appendChild(cap);
}
