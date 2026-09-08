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
import { drawSignatureCloud, drawPlaceholder } from './plot';

let worker: Worker | null = null;

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

function renderCounter(
  signatures: number,
  observed: number,
  restarts: number,
  found: number,
  target: number,
  phase: string,
): void {
  kvList(byId('sig-counter'), [
    { k: 'phase', v: phase },
    { k: 'signatures consumed', v: String(signatures) },
    { k: 'signatures observed (incl. hold-out)', v: String(observed) },
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
  drawSignatureCloud(byId<HTMLCanvasElement>('break2-canvas'), leaks, key.R, { i: 0, j: 1 }, {
    showParallelepiped: signer === 'roundoff',
    recovered,
  });
  const hint = byId('cloud-hint');
  hint.textContent =
    signer === 'roundoff'
      ? `Each dot is one signature offset s - h, projected to two dimensions. The outline is the true projection of P(R) -- a zonogon, computed exactly from the secret rows, not a drawn box. Round-off signing fills it uniformly, corners included, and the corners are what leak the basis.`
      : `The same plot with Klein (Gaussian) signing. The cloud is round. There are no corners to learn, which is precisely why Falcon samples instead of rounding.`;
}

export function initBreak2(key: GghKey, seed: number): void {
  drawPlaceholder(
    byId<HTMLCanvasElement>('break2-canvas'),
    'Collect signatures to see the parallelepiped',
  );
  renderCounter(0, 0, 0, 0, key.n, 'idle');
  const caveat = dimensionCaveat(key.n);
  retire(byId('verdict-break2'));
  byId('break2-note').textContent =
    caveat ??
    `Signing key uses GGH's own k = round(sqrt(n)*l), the right rule for a signature key. ` +
      `Dimension ${key.n}. The attack reports the signatures it actually consumed; nothing here ` +
      `is a stated constant.`;
  previewCloud(key, 'roundoff', seed);
}

export function cancelBreak2(): void {
  if (worker) {
    worker.terminate();
    worker = null;
  }
  setRunning(false);
}

export function runBreak2InWorker(key: GghKey, seed: number, signer: SignerKind): void {
  cancelBreak2();
  setRunning(true);
  previewCloud(key, signer, seed);

  const caveat = dimensionCaveat(key.n);
  if (caveat) {
    verdict(byId('verdict-break2'), 'warn', 'DIMENSION TOO SMALL TO READ', caveat, 'fail');
  }

  worker = makeWorker();
  worker.onerror = (e) => {
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
    const msg = ev.data;
    if (msg.kind === 'progress') {
      renderCounter(
        msg.progress.signatures,
        msg.progress.observed,
        msg.progress.restarts,
        msg.progress.directionsFound,
        msg.progress.target,
        msg.progress.phase,
      );
      return;
    }
    if (msg.kind === 'error') {
      verdict(byId('verdict-break2'), 'warn', 'ATTACK ERRORED', msg.message, 'fail');
      setRunning(false);
      return;
    }

    // done
    renderCounter(
      msg.signaturesConsumed,
      msg.totalSignaturesObserved,
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
    if (msg.ok) {
      verdict(
        target,
        'bad',
        'SECRET BASIS RECOVERED - FORGERIES ACCEPTED',
        `Recovered the rows of R up to sign and permutation from ${msg.signaturesConsumed} ` +
          `signatures, then signed fresh messages with them. The real verifier -- which knows ` +
          `only the public basis and the published norm bound -- accepted every one. ` +
          `Held-out sum a^4 came out ${fx(d.sumA4HeldOut, 3)}, against 0 for a signature scheme ` +
          `that leaks nothing. This is recovery up to sign and order, not "R" itself.`,
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
