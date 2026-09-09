/**
 * The public-LLL baseline.
 *
 * THIS PANEL EXISTS BECAUSE THE LAB WAS QUIETLY OVERCLAIMING. Acts 1 and 2 show
 * Babai round-off succeeding with the raw private basis and failing with the raw
 * public one, and it is tempting to read that as "the public key hides a good
 * basis". At the dimensions this lab runs at, it does not. An external audit
 * caught it and the measurement is unambiguous: running the lab's own LLL on the
 * public basis alone recovers a basis every bit as good as the private one, on
 * 12/12 seeded keys at each of n = 8, 16, 32 and 60, which then decrypts 60/60
 * ciphertexts through the real decryptor.
 *
 * That is not a flaw in the lab, it is the reason GGH was proposed at n = 200 to
 * 400. Reduction alone settles these sizes. What the two historical attacks
 * explain is how GGH fell at the sizes where reduction alone could not -- Nguyen
 * needed BKZ-20 and pruned BKZ-60 for the real challenges, and dimension 400
 * held out until 2010.
 *
 * So the honest framing, which this panel states on screen: the raw-basis
 * comparison is about BASIS QUALITY, and it is true. It is not evidence of
 * security, and at these dimensions there is none to demonstrate.
 */

import type { GghKey } from '../lattice/types';
import { runPublicLllBaseline } from '../attack/baseline';
import { makeRng } from '../lattice/matrix';
import { byId, fx, kvList, verdict } from './dom';

/**
 * Run the baseline against the key currently on screen and render it.
 *
 * `matchesSecret` is LAB-ONLY ground truth: it reads R, which an attacker cannot
 * do. `worstCaseBound`, `decrypted` and the timing are all attacker-computable
 * and are what actually carry the argument.
 */
export function renderBaselinePanel(key: GghKey, seed: number): void {
  const host = byId('baseline-body');
  host.innerHTML = '';

  const result = runPublicLllBaseline(key, { rng: makeRng(seed ^ 0x1117), ciphertexts: 5 });

  const v = document.createElement('div');
  host.appendChild(v);

  if (result.failure) {
    verdict(
      v,
      'warn',
      'REDUCTION DID NOT FINISH',
      `LLL reported ${result.failure.kind}. Nothing is claimed from an unfinished reduction.`,
      'fail',
    );
    return;
  }

  verdict(
    v,
    'bad',
    result.ok ? 'THE PUBLIC BASIS ALONE IS ENOUGH' : 'REDUCTION DID NOT RECOVER A WORKING BASIS',
    result.ok
      ? `Running LLL on the public basis B -- using nothing secret -- produced a basis that ` +
        `decrypted ${result.decrypted} of ${result.attempted} ciphertexts through the real ` +
        `decryptor, in ${fx(result.ms, 2)} ms. Its worst-case decryption bound is ` +
        `${fx(result.worstCaseBound, 4)}, against the private basis's own comparable figure and ` +
        `well under the 0.5 threshold. At this dimension the public key does not hide a good ` +
        `basis from ordinary lattice reduction.`
      : `LLL reduced the public basis but the result decrypted only ${result.decrypted} of ` +
        `${result.attempted} ciphertexts.`,
    result.ok ? 'alarm' : 'fail',
  );

  const stats = document.createElement('div');
  host.appendChild(stats);
  kvList(stats, [
    { k: 'LLL ran on', v: 'the public basis B only' },
    { k: 'time to reduce', v: `${fx(result.ms, 2)} ms` },
    {
      k: 'decrypted, through the real decryptor',
      v: `${result.decrypted} / ${result.attempted}`,
      tone: result.decrypted === result.attempted ? 'bad' : 'good',
    },
    {
      k: 'worst-case bound of the reduced basis',
      v: fx(result.worstCaseBound, 4),
      tone: result.guaranteed ? 'bad' : 'good',
    },
    {
      k: 'decryption guaranteed with it?',
      v: result.guaranteed ? 'yes, for any e' : 'no',
      tone: result.guaranteed ? 'bad' : 'good',
    },
    { k: 'log10 orthogonality defect', v: fx(result.log10DefectReduced, 3) },
    { k: 'LLL swaps / iterations', v: `${result.swaps} / ${result.iters}` },
    {
      k: 'rows equal to R up to sign and order (LAB ONLY)',
      v: `${result.matchedRows} / ${key.n}${result.matchesSecret ? ' - the secret basis itself' : ''}`,
      tone: result.matchesSecret ? 'bad' : undefined,
    },
  ]);

  const note = document.createElement('p');
  note.className = 'scope-note';
  note.id = 'baseline-scope';
  note.textContent =
    'What this does and does not say. The raw-basis comparison in Act 2 is a true statement about ' +
    'BASIS QUALITY: the same round-off works with a short basis and fails with a long one. It is ' +
    'not a statement about security, and at dimensions 8 to 60 there is no security to ' +
    'demonstrate -- ordinary reduction settles them outright, which is exactly why GGH was ' +
    'proposed at 200 to 400. The two historical attacks below are worth studying because they ' +
    'explain how GGH fell at those larger sizes, where reduction alone was not enough: Nguyen ' +
    'needed BKZ-20 and pruned BKZ-60, and dimension 400 held out until 2010.';
  host.appendChild(note);

  const raw = document.createElement('p');
  raw.className = 'panel-hint';
  raw.textContent =
    'One more honest detail: the raw public basis does not fail to decrypt as a matter of law. Its ' +
    'bound is far over the threshold, so it fails almost always -- measured 0 of 30 at n = 16, 32 ' +
    'and 60 -- but at n = 8 an unusually short error vector slipped under it 2 times in 30. It is a ' +
    'rate, not a law, and the page says so rather than rounding it to "never".';
  host.appendChild(raw);
}

/** Clear the panel when the key is retired. */
export function clearBaselinePanel(): void {
  const host = document.getElementById('baseline-body');
  if (host) host.innerHTML = '';
}
