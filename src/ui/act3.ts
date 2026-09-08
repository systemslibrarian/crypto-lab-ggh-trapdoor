/**
 * Act 3 -- Break 1, driven one step at a time.
 *
 * The stepper exists so the learner watches the attack happen rather than
 * reading that it happened. Each step renders the number it actually produced.
 *
 * The failure evidence here is the part that had to be measured rather than
 * guessed. The obvious story -- "with a non-congruent error the division by 6
 * comes out fractional" -- is FALSE and was measured false 1120 times out of
 * 1120: m0 is by construction the exact solution of the congruence, so
 * c + s - m0*B is identically zero mod 6 and the division always succeeds. A UI
 * built on that story would show nothing, ever. What actually separates a
 * working attack from a broken one, with zero overlap in 1120 trials, is the
 * shortest reduced row norm against its expected value sqrt(n+1), the {+1,-1}
 * pattern check, and the re-encryption check.
 */

import type { Ciphertext, GghKey, Mat } from '../lattice/types';
import { Break1Stepper, type Break1Step } from '../attack/break1';
import { byId, fx, retire, verdict } from './dom';

let stepper: Break1Stepper | null = null;

function stepTitle(step: Break1Step): string {
  switch (step.kind) {
    case 'mod6':
      return 'Solve for m mod 6';
    case 'divide':
      return 'Divide out the known part';
    case 'embed':
      return 'Embed the residual problem and run LLL';
    case 'readoff':
      return 'Read the error off the shortest vector';
    case 'recover':
      return 'Recover the message';
    case 'verify':
      return 'Verify by re-encryption';
  }
}

function stepDetail(step: Break1Step, n: number): string {
  switch (step.kind) {
    case 'mod6':
      return step.ok
        ? `B is invertible mod 2 and mod 3, so the CRT gives m mod 6 exactly.`
        : `B is singular mod ${step.singular?.modulus ?? 6}. This key cannot be attacked this way; generate another.`;
    case 'divide':
      return step.ok
        ? `(c + s - m0*B) / 6 came out an exact integer vector, as it always must. The residual error is now in {0,-1}^n instead of {+-3}^n.`
        : `Division was not exact at coordinate ${step.firstInexactIndex}.`;
    case 'embed':
      return (
        `Target reduced mod the public lattice: max |coordinate| ${step.targetMaxAbsBefore.toExponential(2)} ` +
        `to ${step.targetMaxAbsAfter.toExponential(2)}. Largest Gram entry ${step.gramMaxAbs.toExponential(2)}, ` +
        `largest integer touched ${step.guardMax.toExponential(2)} against 2^53. ` +
        `LLL: ${step.lllIters} iterations, ${step.lllSwaps} swaps.`
      );
    case 'readoff':
      return (
        `Shortest reduced row has norm ${fx(step.minRowNorm, 4)}; a planted error vector would give ` +
        `exactly sqrt(${n + 1}) = ${fx(step.expectedMinRowNorm, 4)}. Ratio ${fx(step.normRatio, 3)}. ` +
        `${step.ok ? 'A row matches the {+1,-1} pattern.' : 'No row matches the {+1,-1} pattern.'}`
      );
    case 'recover':
      return step.ok
        ? `m = m0 + 6*m'. ${step.candidates} candidate vector(s) considered.`
        : `No candidate produced a message. ${step.candidates} tried.`;
    case 'verify':
      return step.ok
        ? `c - m*B is a legal error vector: every entry is +-3. This is the check an attacker runs; it never looks at the real message.`
        : step.tried === 0
          ? `Nothing to verify: LLL returned no vector with the embedding coordinate, so the attack produced no candidate at all.`
          : `Re-encryption rejects the candidate: c - m*B is not a legal error vector. ${step.tried} candidate(s) tried.`;
  }
}

function renderSteps(n: number): void {
  const list = byId('break1-steps');
  list.innerHTML = '';
  const steps = stepper?.steps ?? [];
  for (const step of steps) {
    const li = document.createElement('li');
    li.className = step.ok ? 'step-ok' : 'step-bad';
    const strong = document.createElement('strong');
    strong.textContent = stepTitle(step);
    li.appendChild(strong);
    const note = document.createElement('span');
    note.textContent = step.note;
    li.appendChild(note);
    const detail = document.createElement('span');
    detail.className = 'step-detail';
    detail.textContent = stepDetail(step, n);
    li.appendChild(detail);
    list.appendChild(li);
  }
  byId('act-3').dataset.step = String(steps.length);
}

/** Start a fresh Break 1 run against this ciphertext. */
export function resetBreak1(ct: Ciphertext, key: GghKey, Binv: Mat): void {
  stepper = new Break1Stepper(ct.c, key.B, { Binv });
  renderSteps(key.n);
  byId<HTMLButtonElement>('btn-break1-step').disabled = false;
  retire(byId('verdict-break1'));
  byId('negative-claim').textContent = '';
  byId('break1-note').textContent =
    'Step through the attack. It uses only the public basis and the ciphertext.';
}

/** Advance one step, and render the verdict once the run is finished. */
export function stepBreak1(key: GghKey): void {
  if (!stepper) return;
  stepper.next();
  renderSteps(key.n);
  const btn = byId<HTMLButtonElement>('btn-break1-step');
  btn.disabled = stepper.done;
  if (!stepper.done) return;

  const steps = stepper.steps;
  const last = steps[steps.length - 1];
  const readoff = steps.find((s) => s.kind === 'readoff');
  const verified = last.kind === 'verify' && last.ok;
  const target = byId('verdict-break1');

  const negative = byId('negative-claim');
  if (verified) {
    // THE NEGATIVE CLAIM (master template 4.1d), and its evidence fixture.
    //
    // The fixture is this exact state: the legitimate owner decrypted the
    // ciphertext successfully with the private basis -- the page renders a green
    // DECRYPTED verdict for it -- and the attacker has now recovered the SAME
    // message from the public basis alone. Every check this page performs
    // reports success, and confidentiality is absent anyway.
    //
    // The claim is scoped to this construction, not to the field: it is a
    // statement about GGH encryption at these parameters, and it is false of
    // lattice encryption in general (ML-KEM is not recoverable this way).
    negative.textContent =
      'What this does not buy: a successful decryption is not evidence of confidentiality. ' +
      'The DECRYPTED verdict above is genuine -- the private basis really did recover the ' +
      'message -- and the same message has just been recovered from the public basis and the ' +
      'ciphertext alone. Both checks report success at the same time. GGH encryption at these ' +
      'parameters provides no confidentiality against an attacker who knows Nguyen 1999.';
    // An attack that WORKS is an alarm, not a success: the system is broken.
    verdict(
      target,
      'bad',
      'MESSAGE RECOVERED - GGH ENCRYPTION BROKEN',
      `The message was recovered from the public basis and the ciphertext alone, and the ` +
        `re-encryption check confirms it. The private basis was never used or needed. ` +
        `The attack works because every entry of e is +-3, so all of them are congruent ` +
        `to 3 mod 6 -- not because the error is small.`,
      'alarm',
    );
  } else {
    negative.textContent = '';
    const ratio = readoff && readoff.kind === 'readoff' ? readoff.normRatio : NaN;
    verdict(
      target,
      'ok',
      'ATTACK FAILED',
      `The mod-6 step still ran and the division by 6 was still exact -- it always is, because ` +
        `m0 solves the congruence by construction. What broke is that m0 is now the wrong ` +
        `residue, so the residual problem has no short planted vector. LLL returned a shortest ` +
        `row ${Number.isFinite(ratio) ? `${fx(ratio, 2)}x` : 'many times'} longer than the ` +
        `sqrt(${key.n + 1}) a real solution would give, and re-encryption rejects every candidate. ` +
        `One coordinate that is not +-3 is enough.`,
      // 'fail' is the OPERATION (the attack did not recover the message); the
      // green colour is the SYSTEM (nothing was broken). See dom.ts.
      'fail',
    );
  }
}

/** Clear the act. Used on re-key and on an error-mode change. */
export function clearBreak1(): void {
  stepper = null;
  byId('break1-steps').innerHTML = '';
  byId('negative-claim').textContent = '';
  byId('act-3').dataset.step = '0';
  byId<HTMLButtonElement>('btn-break1-step').disabled = true;
}
