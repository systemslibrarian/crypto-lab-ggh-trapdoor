/**
 * Act 1 -- two bases, one lattice.
 *
 * Shows invariant I1 as a worked proof rather than a claim: the page recovers
 * U and V from R and B alone and displays the four exact integer checks that
 * force det(U) = +-1. It then reports the orthogonality defect of each basis,
 * which is the number the trapdoor actually consists of.
 */

import type { GghKey } from '../lattice/types';
import { makeRng } from '../lattice/matrix';
import { proveSameLattice } from '../lattice/invariants';
import { log10AbsDet, log10OrthogonalityDefect, maxAbs, type MulStats } from '../lattice/matrix';
import { byId, fx, kvList, matrixTable, verdict } from './dom';
import { drawBases, renderLegend, sampleLatticePoints } from './plot';

export function renderAct1(key: GghKey): void {
  const stats: MulStats = { maxIntermediate: 0 };
  const proof = proveSameLattice(key.R, key.B, { stats });

  const target = byId('i1-proof');
  target.innerHTML = '';

  verdict(
    target,
    proof.ok ? 'ok' : 'bad',
    proof.ok ? 'SAME LATTICE' : 'PROOF FAILED',
    proof.reason,
  );

  // The four exact checks stay VISIBLE: they are the proof itself, not detail.
  // What moves behind a disclosure below is the numeric headroom and the
  // recovered transform -- internals an expert wants and a newcomer does not.
  const list = document.createElement('div');
  target.appendChild(list);
  kvList(list, [
    {
      k: 'every entry an exact integer < 2^53',
      v: proof.checks.entriesSafe ? 'yes' : 'no',
      tone: proof.checks.entriesSafe ? 'good' : 'bad',
    },
    {
      k: 'U * R = B  (so L(B) is inside L(R))',
      v: proof.checks.uTimesREqualsB ? 'exact' : 'FAILS',
      tone: proof.checks.uTimesREqualsB ? 'good' : 'bad',
    },
    {
      k: 'V * B = R  (so L(R) is inside L(B))',
      v: proof.checks.vTimesBEqualsR ? 'exact' : 'FAILS',
      tone: proof.checks.vTimesBEqualsR ? 'good' : 'bad',
    },
    {
      k: 'U * V = I  (so det U = +-1)',
      v: proof.checks.uTimesVIsIdentity ? 'exact' : 'FAILS',
      tone: proof.checks.uTimesVIsIdentity ? 'good' : 'bad',
    },
  ]);

  const note = document.createElement('p');
  note.className = 'panel-hint';
  note.textContent =
    'No determinant is computed anywhere in this proof. det B reaches 10^' +
    log10AbsDet(key.B).toFixed(0) +
    ' at this size, which no double can hold; two integer matrices with U*V = I ' +
    'force det U = +-1 without ever forming one.';
  target.appendChild(note);

  const deep = document.createElement('details');
  deep.id = 'i1-internals';
  const summary = document.createElement('summary');
  summary.textContent = 'Numeric headroom, and the transform U recovered from R and B';
  deep.appendChild(summary);
  const headroom = document.createElement('div');
  deep.appendChild(headroom);
  kvList(headroom, [
    { k: 'largest value touched', v: stats.maxIntermediate.toExponential(2) },
    {
      k: 'headroom under 2^53',
      v: `${(Number.MAX_SAFE_INTEGER / Math.max(stats.maxIntermediate, 1)).toExponential(1)}x`,
      tone: 'good',
    },
  ]);
  // matrixTable() empties whatever container it is given, so it gets its own.
  // Passing the panel here wiped the verdict and all four checks above it -- the
  // panel still looked populated, which is exactly why the claims suite checks
  // the verdict against the rows rather than just that something rendered.
  if (proof.U) {
    const matrixHost = document.createElement('div');
    deep.appendChild(matrixHost);
    matrixTable(matrixHost, proof.U, 'U = B * R inverse, recovered from R and B alone');
  }
  target.appendChild(deep);

  // ---- basis shape ----
  const defectR = log10OrthogonalityDefect(key.R);
  const defectB = log10OrthogonalityDefect(key.B);
  kvList(byId('defect-table'), [
    { k: 'dimension', v: String(key.n) },
    { k: 'R = k*I + E, k', v: String(key.k) },
    { k: 'noise half-width l', v: String(key.l) },
    { k: 'largest entry of R', v: String(maxAbs(key.R)), tone: 'good' },
    { k: 'largest entry of B', v: String(maxAbs(key.B)), tone: 'bad' },
    { k: 'log10 orthogonality defect, R', v: fx(defectR, 2), tone: 'good' },
    { k: 'log10 orthogonality defect, B', v: fx(defectB, 2), tone: 'bad' },
    { k: 'per dimension, R', v: fx(defectR / key.n, 3), tone: 'good' },
    { k: 'per dimension, B', v: fx(defectB / key.n, 3), tone: 'bad' },
    { k: 'keys drawn for det coprime to 6', v: String(key.keygenAttempts) },
  ]);

  // Real lattice points, sampled deterministically from the key so the picture
  // is reproducible and is genuinely of L(R) = L(B) rather than a drawn grid.
  const points = sampleLatticePoints(key.R, makeRng(key.n * 7919 + key.k));
  const legend = drawBases(byId<HTMLCanvasElement>('basis-canvas'), key.R, key.B, { i: 0, j: 1 }, points);
  renderLegend(byId('basis-legend'), legend);
}
