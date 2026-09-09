/**
 * Act 4 -- Break 2, the Nguyen-Regev parallelepiped attack, in a Web Worker.
 *
 * A NOTE ON THE KEY THIS ACT USES. Acts 1-3 key with the shipped `gghK`, which
 * is large enough to guarantee decryption (invariant I2). Break 2 attacks a
 * SIGNATURE scheme, where I2 does not apply at all -- and the larger k makes the
 * attack about 16x more expensive, because the lift `round(u*L)` must beat an
 * absolute 0.5 threshold while ||L|| grows with k, so the signature requirement
 * scales as k^2. Measured at n=8: 4000-16000 signatures with the 1997 paper's k,
 * against 64000-128000 with the decryption k.
 *
 * So this act keys with the paper's `k = round(sqrt(n)*l)` -- GGH's own rule,
 * and the right one for a signature key. That is stated on the page rather than
 * done quietly, because using a different key here than in Acts 1-3 is exactly
 * the sort of thing a demo could use to flatter its own attack.
 */

import type { GghKey, Mat } from '../lattice/types';
import { dimensionCaveat, MIN_DEMO_DIM } from '../attack/break2';
import { collectLeaks, makeRoundOffSigner } from '../sign/sign';
import { makeKleinSigner } from '../sign/klein';
import { inverse, makeRng } from '../lattice/matrix';
import type { Break2Request, Break2Response, SignerKind } from '../worker/break2.worker';
import { byId, fx, kvList, retire, verdict } from './dom';
import { drawSignatureCloud, drawPlaceholder, renderLegend } from './plot';

let worker: Worker | null = null;

/**
 * The explicit lifecycle of the descent.
 *
 * Modelled as a value rather than inferred from which buttons are disabled. An
 * audit found the previous version had no cancelled state at all: cancelling
 * silently left the last progress numbers on screen, so a reader could not tell
 * a cancelled run from one still going. Each state has its own rendered status.
 */
export type Break2Phase =
  | 'idle'
  | 'running'
  | 'cancelled'
  | 'error'
  | 'failed'
  | 'succeeded';

let phase: Break2Phase = 'idle';
/** Incremented per run so a late message from a terminated worker is ignored. */
let runToken = 0;
/** Progress arrives once per restart (~35 ms). Announcing every one would flood
 *  a screen reader, so the live region is updated on a fixed cadence and the
 *  numeric readout is refreshed every time. */
let lastAnnounce = 0;
const ANNOUNCE_MS = 2000;

function setPhase(next: Break2Phase): void {
  phase = next;
  byId('act-4').dataset.phase = next;
}

/** The current lifecycle state, for tests and for the status line. */
export function break2Phase(): Break2Phase {
  return phase;
}

/** Vite rewrites this to a base-prefixed, hashed chunk. The URL must be a static literal. */
function makeWorker(): Worker {
  return new Worker(new URL('../worker/break2.worker.ts', import.meta.url), {
    type: 'module',
  });
}

function setRunning(running: boolean): void {
  byId<HTMLButtonElement>('btn-break2-run').disabled = running;
  byId<HTMLButtonElement>('btn-break2-gaussian').disabled = running;
  byId<HTMLButtonElement>('btn-break2-cancel').disabled = !running;
}

/**
 * The live counter.
 *
 * Training, held-out and total are reported as three separate numbers. Each rung
 * draws N training signatures AND N held-out ones, so the victim actually
 * published 2N -- reporting "recovered from N" understates the oracle cost by
 * half, which an audit flagged.
 */
function renderCounter(
  training: number,
  heldOut: number,
  total: number,
  restarts: number,
  found: number,
  target: number,
  phase: string,
): void {
  kvList(byId('sig-counter'), [
    { k: 'phase', v: phase },
    { k: 'signatures consumed (training)', v: String(training) },
    { k: 'signatures held out (scoring only)', v: String(heldOut) },
    { k: 'total oracle signatures observed', v: String(total), tone: 'bad' },
    { k: 'descent restarts', v: String(restarts) },
    { k: 'basis directions found', v: `${found} / ${target}`, tone: found >= target ? 'good' : undefined },
  ]);
}

/**
 * Draw the cloud from a locally generated sample, so there is something to see
 * immediately and again once the attack finishes.
 *
 * `recovered`, when given, overlays the rows the attack actually found. It is
 * drawn in the SAME call as the cloud rather than in a second one -- drawing it
 * separately would just be overwritten by the next redraw.
 */
function previewCloud(
  key: GghKey,
  signer: SignerKind,
  seed: number,
  recovered: Mat | null = null,
  count = 4000,
): void {
  const rng = makeRng(seed ^ 0x5eed);
  const Rinv = inverse(key.R);
  const sign =
    signer === 'klein' ? makeKleinSigner(key.R, rng) : makeRoundOffSigner(key.R, Rinv);
  const leaks = collectLeaks(count, key.n, rng, sign);
  const canvas = byId<HTMLCanvasElement>('break2-canvas');
  const legend = drawSignatureCloud(canvas, leaks, key.R, { i: 0, j: 1 }, {
    showParallelepiped: signer === 'roundoff',
    recovered,
  });
  renderLegend(byId('break2-legend'), legend);
  const hint = byId('cloud-hint');
  hint.textContent =
    signer === 'roundoff'
      ? `Each dot is one signature offset s - h, projected to two dimensions. The outline is the true projection of P(R) -- a zonogon, computed exactly from the secret rows, not a drawn box. Round-off signing fills it uniformly, corners included, and the corners are what leak the basis.`
      : `The same plot with Klein (Gaussian) signing. The cloud is round. There are no corners to learn, which is precisely why Falcon samples instead of rounding.`;
  // The accessible name must describe the state actually rendered, not a single
  // fixed sentence -- it changes when the signer changes.
  canvas.setAttribute(
    'aria-label',
    signer === 'roundoff'
      ? `Signature offsets from round-off signing: ${leaks.length} points filling the projected fundamental parallelepiped of the secret basis, corners included` +
        (recovered ? ', with the recovered basis directions overlaid' : '')
      : `Signature offsets from Klein Gaussian signing: ${leaks.length} points forming a round cloud with no corners`,
  );
}

export function initBreak2(key: GghKey, seed: number): void {
  drawPlaceholder(
    byId<HTMLCanvasElement>('break2-canvas'),
    'Collect signatures to see the parallelepiped',
  );
  renderCounter(0, 0, 0, 0, 0, key.n, 'idle');
  setPhase('idle');
  byId('break2-status').textContent = '';
  const caveat = dimensionCaveat(key.n);
  retire(byId('verdict-break2'));
  byId('break2-note').textContent =
    caveat ??
    `Signing key uses GGH's own k = round(sqrt(n)*l), the right rule for a signature key. ` +
      `Dimension ${key.n}. The attack reports the signatures it actually consumed; nothing here ` +
      `is a stated constant.`;
  previewCloud(key, 'roundoff', seed);
}

/**
 * Stop a running descent.
 *
 * `silent` is used when the key itself is being retired: there is no point
 * announcing "cancelled" about a run whose key no longer exists.
 */
export function cancelBreak2(silent = false): void {
  const wasRunning = worker !== null;
  runToken++;
  if (worker) {
    worker.terminate();
    worker = null;
  }
  setRunning(false);
  if (!wasRunning) return;
  if (silent) {
    setPhase('idle');
    return;
  }
  setPhase('cancelled');
  verdict(
    byId('verdict-break2'),
    'warn',
    'CANCELLED',
    'The descent was stopped before it finished. Nothing was recovered and nothing is claimed; ' +
      'the counts above are how far it had got when it stopped.',
    'fail',
  );
}

export function runBreak2InWorker(key: GghKey, seed: number, signer: SignerKind): void {
  cancelBreak2(true);
  // Stale evidence is cleared at the START of a run, not left to be overwritten
  // when it finishes: a previous run's verdict must never appear to belong to
  // the run now in progress.
  retire(byId('verdict-break2'));
  setPhase('running');
  setRunning(true);
  lastAnnounce = 0;
  const token = ++runToken;
  previewCloud(key, signer, seed);

  const caveat = dimensionCaveat(key.n);
  byId('break2-note').textContent =
    caveat ?? `Running the descent on ${signer === 'klein' ? 'Gaussian' : 'round-off'} signatures.`;

  try {
    worker = makeWorker();
  } catch (err) {
    // Worker construction can throw before any handler is attached -- a blocked
    // module worker, or a bundler URL that did not survive the deploy.
    setPhase('error');
    setRunning(false);
    verdict(
      byId('verdict-break2'),
      'warn',
      'WORKER COULD NOT BE CREATED',
      `The descent runs in a Web Worker and it could not be constructed: ` +
        `${err instanceof Error ? err.message : String(err)}. Nothing was measured.`,
      'fail',
    );
    return;
  }
  worker.onerror = (e) => {
    if (token !== runToken) return;
    setPhase('error');
    verdict(
      byId('verdict-break2'),
      'warn',
      'WORKER FAILED TO START',
      `The descent runs in a Web Worker and it did not load: ${e.message}. Nothing was measured.`,
      'fail',
    );
    setRunning(false);
  };
  worker.onmessageerror = () => {
    if (token !== runToken) return;
    setPhase('error');
    verdict(
      byId('verdict-break2'),
      'warn',
      'WORKER MESSAGE FAILED',
      'A message from the descent worker could not be decoded. Nothing was measured.',
      'fail',
    );
    setRunning(false);
  };

  worker.onmessage = (ev: MessageEvent<Break2Response>) => {
    // A terminated worker can still deliver a queued message. Ignore anything
    // that does not belong to the run currently in progress, or a cancelled run
    // would overwrite its own CANCELLED status with a stale result.
    if (token !== runToken) return;
    const msg = ev.data;
    if (msg.kind === 'progress') {
      renderCounter(
        msg.progress.trainingSignatures,
        msg.progress.heldOutSignatures,
        msg.progress.totalObserved,
        msg.progress.restarts,
        msg.progress.directionsFound,
        msg.progress.target,
        msg.progress.phase,
      );
      // Throttle the SPOKEN milestone. The numbers above refresh every tick;
      // this line is what a screen reader announces, and once per restart would
      // be roughly 30 interruptions a second at n=16.
      const now = Date.now();
      if (now - lastAnnounce > ANNOUNCE_MS) {
        lastAnnounce = now;
        byId('break2-status').textContent =
          `${msg.progress.phase}: ${msg.progress.trainingSignatures} signatures consumed, ` +
          `${msg.progress.directionsFound} of ${msg.progress.target} basis directions found.`;
      }
      return;
    }
    if (msg.kind === 'error') {
      setPhase('error');
      verdict(byId('verdict-break2'), 'warn', 'ATTACK ERRORED', msg.message, 'fail');
      setRunning(false);
      return;
    }

    // done
    byId('break2-status').textContent = '';
    renderCounter(
      msg.trainingSignatures,
      msg.heldOutSignatures,
      msg.totalObserved,
      msg.attempts[msg.attempts.length - 1]?.restarts ?? 0,
      msg.attempts[msg.attempts.length - 1]?.directionsFound ?? 0,
      key.n,
      'finished',
    );

    const d = msg.discriminators;
    const stats = document.createElement('div');
    kvList(stats, [
      { k: 'sum a^4, held out (public)', v: fx(d.sumA4HeldOut, 4), tone: msg.ok ? 'bad' : 'good' },
      { k: 'sum a^4, in sample (overfits)', v: fx(d.sumA4InSample, 4) },
      { k: 'fourth moment, held out', v: fx(d.mom4HeldOut, 6) },
      { k: '1/48 = no structure at all', v: fx(1 / 48, 6) },
      { k: 'mean lift integrality gap', v: fx(d.integralityGap, 3) },
      { k: 'covariance shape deviation', v: fx(d.covarianceShape, 4) },
      { k: 'signature norm bound published', v: fx(msg.boundInf, 1) },
    ]);

    const recovered = msg.rows ? msg.rows.map((r) => Float64Array.from(r)) : null;
    previewCloud(key, msg.gaussian ? 'klein' : 'roundoff', seed, recovered);

    const target = byId('verdict-break2');
    // TWO INDEPENDENT OUTCOMES, rendered separately. An audit found the page
    // saying "SECRET BASIS RECOVERED" on the strength of accepted forgeries
    // alone. Forging proves the candidate is a good basis of this lattice; it
    // does NOT prove it is the secret rows. The distinction matters here more
    // than usual, because ordinary LLL on the public basis also produces a
    // basis good enough to forge with -- see the baseline exhibit in Act 2.
    //
    // Only `forgeryOk` is attacker-observable. `groundTruthRecovered` reads the
    // secret and is lab scoring; null means it was not scored, which must never
    // be rendered as "not recovered".
    const groundTruth =
      msg.groundTruthRecovered === null
        ? 'not scored'
        : msg.groundTruthRecovered
          ? 'yes'
          : 'no';
    const checks = document.createElement('div');
    kvList(checks, [
      {
        k: 'Forgery check (attacker-observable)',
        v: msg.forgeryOk ? 'verifier accepted' : 'verifier rejected',
        tone: msg.forgeryOk ? 'bad' : 'good',
      },
      {
        k: 'Ground-truth recovery (lab only)',
        v:
          groundTruth === 'not scored'
            ? 'not scored'
            : `${groundTruth}${msg.groundTruthMatched !== null ? ` (${msg.groundTruthMatched}/${key.n} rows)` : ''}`,
        tone: msg.groundTruthRecovered === true ? 'bad' : msg.groundTruthRecovered === false ? 'good' : undefined,
      },
    ]);
    byId('break2-checks').innerHTML = '';
    byId('break2-checks').appendChild(checks);

    if (msg.ok && msg.groundTruthRecovered === true) {
      verdict(
        target,
        'bad',
        'SECRET BASIS RECOVERED - FORGERIES ACCEPTED',
        `Both checks passed. The recovered rows match R up to sign and permutation ` +
          `(${msg.groundTruthMatched}/${key.n}), and fresh signatures made with them were accepted ` +
          `by the real verifier, which knows only the public basis and the published bound. ` +
          `It took ${msg.trainingSignatures} training signatures plus ${msg.heldOutSignatures} ` +
          `held out -- ${msg.totalObserved} oracle signatures observed in total. Held-out sum a^4 ` +
          `${fx(d.sumA4HeldOut, 3)}. This is recovery up to sign and order, not "R" itself.`,
        'alarm',
      );
    } else if (msg.ok) {
      verdict(
        target,
        'bad',
        'FORGERY-CAPABLE BASIS FOUND',
        `The real verifier accepted every fresh signature made with the recovered basis, from ` +
          `${msg.trainingSignatures} training plus ${msg.heldOutSignatures} held out = ` +
          `${msg.totalObserved} oracle signatures observed. That is forgery capability, and it is ` +
          `already fatal for a signature scheme. It is NOT the same claim as recovering the secret ` +
          `rows: the lab's own ground-truth check says ${groundTruth}` +
          `${msg.groundTruthMatched !== null ? ` (${msg.groundTruthMatched} of ${key.n} rows matched)` : ''}. ` +
          `A different good basis of the same lattice forges just as well.`,
        'alarm',
      );
    } else if (msg.gaussian) {
      verdict(
        target,
        'ok',
        'ATTACK FAILED - GAUSSIAN SIGNATURES HOLD',
        `${msg.reason} Held-out sum a^4 is ${fx(d.sumA4HeldOut, 4)}, essentially zero: the ` +
          `fourth moment is flat at 1/48 in every direction, so there is no distinguished ` +
          `direction to descend to. The in-sample figure reads ${fx(d.sumA4InSample, 3)} and is ` +
          `pure overfitting -- that is why the hold-out split is built in. The lift gap is ` +
          `${fx(d.integralityGap, 3)}, which is what rounding noise looks like. Same lattice, ` +
          `same code, same signature count; only the sampler changed.`,
        // The attack failed, so the OPERATION is 'fail'; the colour is green
        // because that is the system holding. See dom.ts.
        'fail',
      );
    } else {
      verdict(
        target,
        'warn',
        'NOT RECOVERED WITHIN THE CAP',
        `${msg.reason} The cap was ${msg.capN} signatures and the attack is reporting failure ` +
          `rather than claiming a success it did not verify. Held-out sum a^4 ` +
          `${fx(d.sumA4HeldOut, 4)}.`,
        'fail',
      );
    }
    byId('sig-counter').appendChild(stats);
    setPhase(msg.ok ? 'succeeded' : 'failed');
    setRunning(false);
    worker?.terminate();
    worker = null;
  };

  const req: Break2Request = {
    kind: 'run',
    R: key.R.map((r) => Array.from(r)),
    B: key.B.map((r) => Array.from(r)),
    signer,
    seed,
    startN: 1000,
    // Measured: the paper-k signature key needs 4000-16000 at n=8 and
    // 16000-64000 at n=16. The cap is generous enough to succeed at the
    // dimensions this act runs at, and low enough to fail honestly rather than
    // run forever.
    capN: key.n <= MIN_DEMO_DIM ? 32000 : 128000,
  };
  worker.postMessage(req);
}
