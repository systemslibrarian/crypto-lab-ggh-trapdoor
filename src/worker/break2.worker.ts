/**
 * The Break 2 descent, off the main thread.
 *
 * WHY THIS ONE AND NOT LLL. The brief expected LLL to need a worker. Measured,
 * it does not: the whole of Break 1 runs in 4.6 ms at n=60, of which LLL is
 * 2.9 ms -- comfortably inside one animation frame. The fourth-moment descent is
 * the part that blocks: ~1 s at the median n=16 configuration and 3.2 s on the
 * worst measured key, because it costs 2*N*n flops per iteration, ~36 iterations
 * per restart, and ~50 restarts. So the worker wraps the descent, and Break 1
 * stays on the main thread where its steps can be animated one at a time.
 *
 * The attack is re-run inside the worker rather than having state shipped in:
 * the signing oracle is a closure over the private basis and cannot cross a
 * postMessage boundary, so the worker is given the key material and builds the
 * oracle itself. That keeps `runBreak2` honest -- it still only ever sees a
 * public key and a signing function, exactly as an attacker would.
 *
 * Progress is posted once per restart (~35 ms at n=16, the measured natural tick
 * granularity), which is what drives the live signature counter.
 */

import type { Mat } from '../lattice/types';
import { inverse, makeRng } from '../lattice/matrix';
import { makeRoundOffSigner, roundOffBoundInf } from '../sign/sign';
import { kleinBoundInf, kleinSigma, makeKleinSigner } from '../sign/klein';
import { publicKey } from '../sign/verify';
import { runBreak2, type Break2Progress } from '../attack/break2';

/** Which signer the victim is using. The attack cannot tell them apart. */
export type SignerKind = 'roundoff' | 'klein';

export interface Break2Request {
  readonly kind: 'run';
  /** Rows of the private basis, sent as plain arrays. */
  readonly R: number[][];
  /** Rows of the public basis. */
  readonly B: number[][];
  readonly signer: SignerKind;
  readonly seed: number;
  readonly capN: number;
  readonly startN: number;
}

export type Break2Response =
  | { kind: 'progress'; progress: Break2Progress }
  | {
      kind: 'done';
      ok: boolean;
      reason: string;
      /** OUTCOME 1, attacker-observable: the public verifier accepted the forgeries. */
      forgeryOk: boolean;
      /**
       * OUTCOME 2, LAB-ONLY: the candidate really is R up to sign and permutation.
       * An attacker cannot compute this. null means it was not scored.
       */
      groundTruthRecovered: boolean | null;
      /** How many candidate rows matched a secret row, for display. */
      groundTruthMatched: number | null;
      /** Signatures the descent trained on. */
      trainingSignatures: number;
      /** Signatures withheld from the descent, used only for scoring. */
      heldOutSignatures: number;
      /** What the victim actually published: training + held out. */
      totalObserved: number;
      capN: number;
      /** Rows recovered, for the plot. Null when the descent never completed. */
      rows: number[][] | null;
      discriminators: {
        sumA4HeldOut: number;
        mom4HeldOut: number;
        sumA4InSample: number;
        integralityGap: number;
        worstIntegralityGap: number;
        covarianceShape: number;
      };
      attempts: Array<{
        signatures: number;
        restarts: number;
        directionsFound: number;
        forgeriesAccepted: number;
        forgeriesAttempted: number;
      }>;
      /** True when the signer was Klein, so the UI can name the negative case. */
      gaussian: boolean;
      /** The signature norm bound this signer published. */
      boundInf: number;
    }
  | { kind: 'error'; message: string };

function toMat(rows: number[][]): Mat {
  return rows.map((r) => Float64Array.from(r));
}

function fromMat(m: Mat | null): number[][] | null {
  return m ? m.map((r) => Array.from(r)) : null;
}

self.onmessage = (ev: MessageEvent<Break2Request>) => {
  const msg = ev.data;
  if (!msg || msg.kind !== 'run') return;
  try {
    const R = toMat(msg.R);
    const B = toMat(msg.B);
    const Rinv = inverse(R);
    const rng = makeRng(msg.seed);

    // Each signer publishes its OWN norm bound. Klein signatures are ~4x longer
    // than round-off ones and would fail the round-off bound outright, so
    // comparing them against one shared bound would rig the negative case.
    // Measured against its own bound, each signer verifies 100% of the time.
    const gaussian = msg.signer === 'klein';
    const sign = gaussian
      ? makeKleinSigner(R, rng)
      : makeRoundOffSigner(R, Rinv);
    const boundInf = gaussian ? kleinBoundInf(kleinSigma(R)) : roundOffBoundInf(R);
    const pub = publicKey(B, boundInf);

    const result = runBreak2({
      pub,
      sign,
      rng,
      startN: msg.startN,
      capN: msg.capN,
      // LAB SCORING ONLY. The attack never consults this -- break2.test.ts
      // deep-equals the whole result with and without it to prove that. It is
      // here so the page can show the second, independent outcome: whether the
      // forging basis is actually the secret one.
      groundTruthR: R,
      onProgress: (progress) => {
        const out: Break2Response = { kind: 'progress', progress };
        (self as unknown as Worker).postMessage(out);
      },
    });

    const done: Break2Response = {
      kind: 'done',
      ok: result.ok,
      reason: result.reason,
      forgeryOk: result.forgeryOk,
      groundTruthRecovered: result.groundTruthRecovered,
      groundTruthMatched: result.groundTruthMatch ? result.groundTruthMatch.matched : null,
      trainingSignatures: result.trainingSignatures,
      heldOutSignatures: result.heldOutSignatures,
      totalObserved: result.totalObserved,
      capN: result.capN,
      rows: fromMat(result.Rhat),
      discriminators: {
        sumA4HeldOut: result.discriminators.sumA4HeldOut,
        mom4HeldOut: result.discriminators.mom4HeldOut,
        sumA4InSample: result.discriminators.sumA4InSample,
        integralityGap: result.discriminators.integralityGap,
        worstIntegralityGap: result.discriminators.worstIntegralityGap,
        covarianceShape: result.discriminators.covarianceShape,
      },
      attempts: result.attempts.map((a) => ({
        signatures: a.signatures,
        restarts: a.restarts,
        directionsFound: a.directionsFound,
        forgeriesAccepted: a.forgeriesAccepted,
        forgeriesAttempted: a.forgeriesAttempted,
      })),
      gaussian,
      boundInf,
    };
    (self as unknown as Worker).postMessage(done);
  } catch (err) {
    const out: Break2Response = {
      kind: 'error',
      message: err instanceof Error ? err.message : String(err),
    };
    (self as unknown as Worker).postMessage(out);
  }
};
