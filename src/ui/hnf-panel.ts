/**
 * The Hermite Normal Form public key (Micciancio, CaLC 2001), as a real exhibit.
 *
 * This shipped as an implementation and a test suite but was never wired into
 * the page, while the brief and README described it as a browser exhibit. An
 * external audit caught the gap. Rather than narrow the claim, the exhibit is
 * here: the module already did the hard part.
 *
 * Everything on this panel is computed on demand from the key currently on
 * screen. Nothing is copied from a test.
 *
 * WHY THIS IS THE ONE BIGINT PATH IN THE LAB. The HNF diagonal multiplies to
 * exactly |det R|, which at the shipped parameters is about 10^113 at n=60 --
 * some 97 orders past 2^53. There is no honest way to hold that in a double, so
 * this module, its proof, and this panel are BigInt throughout. Everything else
 * in the lab is Number-safe with measured margin.
 */

import type { GghKey } from '../lattice/types';
import {
  bitsOfInt,
  compareKeySize,
  estimateHnfMs,
  hnf,
  HNF_BENEFITS,
  isHnf,
  proveSameLatticeHnf,
  toBigMat,
  type BigMat,
} from '../lattice/hnf';
import { byId, fx, kvList, verdict } from './dom';

/** Cache per key so flipping the toggle back and forth is free. */
let cache: { key: GghKey; html: DocumentFragment } | null = null;

function bigMatEqLocal(A: BigMat, B: BigMat): boolean {
  if (A.length !== B.length) return false;
  for (let i = 0; i < A.length; i++) {
    if (A[i].length !== B[i].length) return false;
    for (let j = 0; j < A[i].length; j++) if (A[i][j] !== B[i][j]) return false;
  }
  return true;
}

/** Render the first rows/cols of a BigInt matrix, digits truncated for display only. */
function bigMatrixTable(target: HTMLElement, H: BigMat, label: string, max = 8): void {
  const wrap = document.createElement('div');
  wrap.className = 'matrix-scroll';
  wrap.tabIndex = 0;
  wrap.setAttribute('role', 'region');
  wrap.setAttribute('aria-label', label);
  const table = document.createElement('table');
  const rows = Math.min(H.length, max);
  const cols = Math.min(H.length, max);
  for (let i = 0; i < rows; i++) {
    const tr = document.createElement('tr');
    for (let j = 0; j < cols; j++) {
      const td = document.createElement('td');
      const s = H[i][j].toString();
      // Long entries are shown as a digit count rather than silently truncated,
      // so the number's real magnitude is never misrepresented.
      td.textContent = s.length > 12 ? `<${s.length} digits>` : s;
      if (i === j) td.className = 'diag';
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }
  wrap.appendChild(table);
  target.appendChild(wrap);
  const cap = document.createElement('p');
  cap.className = 'panel-hint';
  cap.textContent = `${label} - showing ${rows}x${cols} of ${H.length}x${H.length}. Entries longer than 12 digits are shown as their digit count; none are truncated numerically.`;
  target.appendChild(cap);
}

function details(summaryText: string): HTMLDetailsElement {
  const d = document.createElement('details');
  const s = document.createElement('summary');
  s.textContent = summaryText;
  d.appendChild(s);
  return d;
}

/**
 * Build the HNF exhibit for this key.
 *
 * Computes HNF(R) and HNF(B) so canonicity is DEMONSTRATED rather than asserted:
 * they must come out identical, because the HNF depends only on the lattice.
 */
export function renderHnfPanel(key: GghKey): void {
  const host = byId('hnf-body');
  if (cache && cache.key === key) {
    host.innerHTML = '';
    host.appendChild(cache.html.cloneNode(true));
    return;
  }

  host.innerHTML = '';
  const frag = document.createDocumentFragment();

  const bigR = toBigMat(key.R);
  const bigB = toBigMat(key.B);
  const fromR = hnf(bigR);
  const fromB = hnf(bigB);
  const canonical = bigMatEqLocal(fromR.H, fromB.H);
  const proof = proveSameLatticeHnf(bigR, fromR.H);
  const shape = isHnf(fromR.H);
  const size = compareKeySize(key.B, fromR.H);
  const estimate = estimateHnfMs(key.n);

  const v = document.createElement('div');
  frag.appendChild(v);
  verdict(
    v,
    canonical && proof.ok && shape ? 'ok' : 'bad',
    canonical && proof.ok && shape ? 'CANONICAL AND SAME LATTICE' : 'HNF CHECK FAILED',
    canonical && proof.ok && shape
      ? `HNF(R) and HNF(B) were computed independently and came out identical, which is what ` +
        `"canonical" means: the Hermite normal form depends only on the lattice, not on the basis ` +
        `it was derived from. ${proof.reason}`
      : `${!shape ? 'The result is not in Hermite normal form. ' : ''}` +
        `${!canonical ? 'HNF(R) and HNF(B) differ, so canonicity failed. ' : ''}${proof.reason}`,
    canonical && proof.ok && shape ? 'pass' : 'fail',
  );

  const stats = document.createElement('div');
  frag.appendChild(stats);
  kvList(stats, [
    { k: 'HNF(R) equals HNF(B)?', v: canonical ? 'yes, identical' : 'NO', tone: canonical ? 'good' : 'bad' },
    { k: 'in Hermite normal form?', v: shape ? 'yes' : 'NO', tone: shape ? 'good' : 'bad' },
    {
      k: 'same lattice, proved in BigInt',
      v: proof.ok ? 'both inclusions exact' : 'FAILED',
      tone: proof.ok ? 'good' : 'bad',
    },
    { k: 'product of pivots equals |det R|', v: proof.checks.determinantsMatch ? 'exact' : 'FAILS', tone: proof.checks.determinantsMatch ? 'good' : 'bad' },
    { k: 'bits in |det R|', v: String(bitsOfInt(fromR.d)) },
    { k: 'pivots greater than 1', v: `${size.nontrivialPivots} of ${key.n}` },
    { k: 'public basis B, serialised', v: `${size.basisBits} bits` },
    { k: 'HNF upper triangle, serialised', v: `${size.hnfBits} bits`, tone: size.ratio > 1 ? 'good' : undefined },
    { k: 'size ratio B : HNF', v: `${fx(size.ratio, 2)}x`, tone: size.ratio > 1 ? 'good' : 'bad' },
    { k: 'bits per entry of B', v: fx(size.basisBitsPerEntry, 1) },
    { k: 'HNF computed in', v: `${fx(fromR.ms, 2)} ms` },
    { k: 'BigInt same-lattice proof in', v: `${fx(proof.ms, 2)} ms` },
    {
      k: 'budget estimate for this dimension',
      v: `${fx(estimate.totalMs, 1)} ms${estimate.measured ? ' (measured)' : ' (interpolated)'}`,
      tone: estimate.mainThreadSafe ? 'good' : 'bad',
    },
  ]);

  // The honest size result. Micciancio's factor-n is asymptotic and assumes a
  // fully mixed public basis; this lab mixes gently, so the measured saving is
  // much smaller. Saying so is the point -- the invariant worth noticing is that
  // the HNF's own size does not move when the mixing does.
  const sizeNote = document.createElement('p');
  sizeNote.className = 'panel-hint';
  sizeNote.textContent =
    `Micciancio's headline is asymptotic -- key size from O(n^3 log n) to O(n^2 log n), "a factor n". ` +
    `That n^3 assumes each entry of the public basis needs O(n log n) bits. This lab mixes U gently ` +
    `(6 row operations per row, entries capped at 512), so B costs about ${fx(size.basisBitsPerEntry, 1)} ` +
    `bits per entry and the measured saving here is ${fx(size.ratio, 2)}x, not n. Mix harder and the ` +
    `factor appears -- while the HNF's own size does not move at all, because it depends only on the ` +
    `lattice. That invariance is the real lesson.`;
  frag.appendChild(sizeNote);

  const proofDetails = details('The BigInt same-lattice proof, step by step');
  const proofList = document.createElement('div');
  proofDetails.appendChild(proofList);
  kvList(proofList, [
    { k: 'H is in Hermite normal form', v: proof.checks.hnfShape ? 'yes' : 'NO', tone: proof.checks.hnfShape ? 'good' : 'bad' },
    { k: 'determinants match', v: proof.checks.determinantsMatch ? 'exact' : 'FAILS', tone: proof.checks.determinantsMatch ? 'good' : 'bad' },
    { k: 'T = H * adj(R) / det(R) is integral', v: proof.checks.tIsIntegral ? 'exact' : 'FAILS', tone: proof.checks.tIsIntegral ? 'good' : 'bad' },
    { k: 'T * R = H  (L(H) inside L(R))', v: proof.checks.tTimesREqualsH ? 'exact' : 'FAILS', tone: proof.checks.tTimesREqualsH ? 'good' : 'bad' },
    { k: 'S is integral', v: proof.checks.sIsIntegral ? 'exact' : 'FAILS', tone: proof.checks.sIsIntegral ? 'good' : 'bad' },
    { k: 'S * H = R  (L(R) inside L(H))', v: proof.checks.sTimesHEqualsR ? 'exact' : 'FAILS', tone: proof.checks.sTimesHEqualsR ? 'good' : 'bad' },
    { k: 'T * S = I  (so det T = +-1)', v: proof.checks.tTimesSIsIdentity ? 'exact' : 'FAILS', tone: proof.checks.tTimesSIsIdentity ? 'good' : 'bad' },
  ]);
  frag.appendChild(proofDetails);

  const matrixDetails = details('The canonical basis HNF(R)');
  const matrixHost = document.createElement('div');
  matrixDetails.appendChild(matrixHost);
  bigMatrixTable(matrixHost, fromR.H, 'HNF(R), the canonical public basis');
  frag.appendChild(matrixDetails);

  const benefitDetails = details('What the Hermite normal form actually buys');
  for (const b of HNF_BENEFITS) {
    const h = document.createElement('p');
    const strong = document.createElement('strong');
    strong.textContent = b.title + '. ';
    h.appendChild(strong);
    h.appendChild(document.createTextNode(b.claim));
    benefitDetails.appendChild(h);
    const src = document.createElement('p');
    src.className = 'step-detail';
    src.textContent = `${b.source} — ${b.checkedBy}`;
    benefitDetails.appendChild(src);
  }
  frag.appendChild(benefitDetails);

  cache = { key, html: frag.cloneNode(true) as DocumentFragment };
  host.appendChild(frag);
}

/** Drop the cache when the key changes. */
export function clearHnfPanel(): void {
  cache = null;
  const host = document.getElementById('hnf-body');
  if (host) host.innerHTML = '';
}
