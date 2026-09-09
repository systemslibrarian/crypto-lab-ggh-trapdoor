/**
 * Act 2 -- encrypt, then decrypt twice.
 *
 * The two decrypt buttons call the SAME function with a different basis. That is
 * deliberate: the asymmetry has to come from the basis, not from two different
 * code paths, or the exhibit would be staging its own conclusion.
 *
 * TWO INTERACTION BUGS WERE FIXED HERE, and both were breaking the lesson rather
 * than merely looking untidy:
 *
 *   1. The ciphertext caption was APPENDED to the panel on every encryption
 *      instead of replacing the previous one. Three encryptions left three
 *      captions, and because the error mode can change between them, two could
 *      say "every entry is +-3" while the third said the opposite. There is now
 *      exactly one caption element and it is rewritten in place.
 *
 *   2. Both decryptions wrote to the SAME verdict container, so running the
 *      intended private-then-public sequence replaced DECRYPTED with WRONG
 *      MESSAGE. The one comparison the whole act exists to make erased itself.
 *      The two results are now separate persistent cells inside that container,
 *      plus a comparison sentence that appears once both have been run.
 *
 * `data-verdict` on the container still tracks the most recent decryption, so it
 * remains one machine-readable outcome for the gate and the claims suite.
 */

import type { Ciphertext, GghKey, Mat } from '../lattice/types';
import { decryptBound, latticePointToMessage, reEncryptionCheck, roundOff } from '../lattice/roundoff';
import { SIGMA } from '../lattice/keygen';
import { byId, fx, kvList } from './dom';

/** Which basis a decryption attempt used. */
export type BasisChoice = 'private' | 'public';

/** What the most recent run of each basis produced, so the pair can be compared. */
interface CellState {
  ok: boolean;
  bound: number;
  predicted: boolean;
  wrongCoords: number;
}

const cells: Partial<Record<BasisChoice, CellState>> = {};

/** Forget both results. Called whenever the key or the ciphertext is retired. */
export function clearDecryptResults(): void {
  delete cells.private;
  delete cells.public;
  byId('ciphertext-caption').textContent = '';
}

/** Draw the ciphertext with its error vector called out per coordinate. */
export function renderCiphertext(ct: Ciphertext, sigma = SIGMA): void {
  const strip = byId('ciphertext-strip');
  strip.innerHTML = '';
  for (let i = 0; i < ct.c.length; i++) {
    const cell = document.createElement('div');
    const e = ct.e[i];
    // "odd" here means "not +-sigma": the coordinate that breaks Break 1's
    // congruence. It is marked with a border as well as a colour.
    const isCongruent = Math.abs(e) === sigma;
    cell.className = `strip-cell ${isCongruent ? (e > 0 ? 'e-pos' : 'e-neg') : 'e-odd'}`;
    const c = document.createElement('span');
    c.textContent = String(ct.c[i]);
    const eSpan = document.createElement('span');
    eSpan.className = 'strip-e';
    eSpan.textContent = (e >= 0 ? '+' : '') + String(e);
    cell.appendChild(c);
    cell.appendChild(eSpan);
    cell.title = `coordinate ${i}: c = ${ct.c[i]}, e = ${e}`;
    strip.appendChild(cell);
  }
  // Exactly one caption, rewritten in place.
  const allCongruent = Array.from(ct.e).every((x) => Math.abs(x) === sigma);
  const odd = Array.from(ct.e).filter((x) => Math.abs(x) !== sigma).length;
  byId('ciphertext-caption').textContent = allCongruent
    ? `Top row is c = m*B + e; bottom row is e. Every entry is +-${sigma}, so every entry is congruent to ${sigma} mod ${2 * sigma}. That is the only thing Break 1 needs.`
    : `Top row is c = m*B + e; bottom row is e. ${odd} of ${ct.e.length} coordinates are not +-${sigma} (outlined), so the mod-${2 * sigma} congruence Break 1 depends on no longer holds.`;
}

/** Report invariant I2 for this ciphertext under both bases, side by side. */
export function renderBound(ct: Ciphertext, Rinv: Mat, Binv: Mat): void {
  const withR = decryptBound(ct.e, Rinv);
  const withB = decryptBound(ct.e, Binv);
  kvList(byId('i2-bound'), [
    { k: 'threshold', v: '0.5' },
    {
      k: 'max |e * R inverse|  (private)',
      v: fx(withR.actual),
      tone: withR.predictsSuccess ? 'good' : 'bad',
    },
    {
      k: 'max |e * B inverse|  (public)',
      v: fx(withB.actual),
      tone: withB.predictsSuccess ? 'good' : 'bad',
    },
    { k: 'headroom with R', v: `${fx(withR.margin, 2)}x`, tone: 'good' },
    { k: 'headroom with B', v: `${fx(withB.margin, 2)}x`, tone: 'bad' },
    {
      k: 'worst case over EVERY error, R',
      v: fx(withR.worstCase),
      tone: withR.guaranteed ? 'good' : 'bad',
    },
    {
      k: 'worst case over EVERY error, B',
      v: fx(withB.worstCase),
      tone: withB.guaranteed ? 'good' : 'bad',
    },
    {
      k: 'decryption guaranteed with R?',
      v: withR.guaranteed ? 'yes, for any e' : 'no',
      tone: withR.guaranteed ? 'good' : 'bad',
    },
    // The page's own PREDICTION, printed before either decrypt button is
    // pressed. It is what makes I2 a falsifiable claim rather than a number:
    // the claims suite drives the real decryption afterwards and requires the
    // outcome to match what this row said it would be.
    {
      k: 'predicted outcome with R',
      v: withR.predictsSuccess ? 'will decrypt' : 'will fail',
      tone: withR.predictsSuccess ? 'good' : 'bad',
    },
    {
      k: 'predicted outcome with B',
      v: withB.predictsSuccess ? 'will decrypt' : 'will fail',
      tone: withB.predictsSuccess ? 'good' : 'bad',
    },
  ]);
}

function renderCell(which: BasisChoice, state: CellState, n: number): HTMLElement {
  const box = document.createElement('div');
  box.className = `result-cell ${state.ok ? 'verdict-ok' : 'verdict-bad'}`;
  box.id = `result-${which}`;
  box.dataset.outcome = state.ok ? 'pass' : 'fail';

  const head = document.createElement('p');
  head.className = 'result-head';
  const icon = document.createElement('span');
  icon.className = 'verdict-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = state.ok ? 'OK' : '!!';
  const label = document.createElement('span');
  label.className = 'verdict-label';
  label.textContent = state.ok ? 'DECRYPTED' : 'WRONG MESSAGE';
  const basis = document.createElement('span');
  basis.className = 'result-basis';
  basis.textContent = which === 'private' ? ' with the private basis R' : ' with the public basis B';
  head.appendChild(icon);
  head.appendChild(label);
  head.appendChild(basis);
  box.appendChild(head);

  const detail = document.createElement('p');
  detail.className = 'result-detail';
  // The prediction is reported as a prediction, and whether it HELD is stated
  // rather than assumed. If the bound ever disagreed with the real decryption
  // that would be a genuine finding about invariant I2, so the page must be able
  // to say so instead of quietly printing "as predicted" either way.
  const agreed = state.predicted === state.ok;
  const predictionPhrase = agreed
    ? `as the bound predicted`
    : `WHICH THE BOUND DID NOT PREDICT -- the bound said it would ` +
      `${state.predicted ? 'decrypt' : 'fail'}`;
  detail.textContent = state.ok
    ? `Deciding number ${fx(state.bound)}, under the 0.5 threshold, ${predictionPhrase}. ` +
      `Re-encryption confirms it: c minus m*B is a legal error vector with every entry +-${SIGMA}.`
    : `Deciding number ${fx(state.bound)}, over the 0.5 threshold, ${predictionPhrase}. ` +
      `Re-encryption rejects it, and ${state.wrongCoords} of ${n} message coordinates are wrong.`;
  box.appendChild(detail);
  return box;
}

/**
 * Run Babai round-off with one basis and report the result.
 *
 * The verdict is decided by the re-encryption check -- the one an attacker or a
 * recipient could actually run -- not by comparing against the message we happen
 * to know, which would make the exhibit unfalsifiable.
 */
export function runDecrypt(
  ct: Ciphertext,
  key: GghKey,
  Rinv: Mat,
  Binv: Mat,
  which: BasisChoice,
): void {
  const basis = which === 'private' ? key.R : key.B;
  const basisInv = which === 'private' ? Rinv : Binv;
  const point = roundOff(ct.c, basis, basisInv);
  const recovered = latticePointToMessage(point, Binv);
  const check = reEncryptionCheck(ct.c, recovered, key.B);
  const bound = decryptBound(ct.e, basisInv);

  let wrongCoords = 0;
  for (let i = 0; i < recovered.length; i++) if (recovered[i] !== ct.m[i]) wrongCoords++;
  cells[which] = {
    ok: check.ok,
    bound: bound.actual,
    predicted: bound.predictsSuccess,
    wrongCoords,
  };

  const target = byId('verdict-decrypt');
  target.innerHTML = '';
  // data-verdict follows the decryption just performed, so there is still one
  // unambiguous machine-readable outcome even though two results are on screen.
  target.dataset.verdict = check.ok ? 'pass' : 'fail';

  for (const side of ['private', 'public'] as const) {
    const state = cells[side];
    if (state) target.appendChild(renderCell(side, state, key.n));
  }

  const priv = cells.private;
  const pub = cells.public;
  const both = priv !== undefined && pub !== undefined;
  if (priv && pub) {
    const compare = document.createElement('p');
    compare.className = 'result-compare';
    compare.textContent =
      priv.ok && !pub.ok
        ? `Same ciphertext, same algorithm, same three lines of arithmetic. Only the basis changed: ` +
          `${fx(priv.bound)} with R against ${fx(pub.bound)} with B, against a threshold of 0.5. ` +
          `That gap is the entire trapdoor.`
        : `Both results are shown above for the same ciphertext. Compare the deciding numbers: ` +
          `${fx(priv.bound)} with R against ${fx(pub.bound)} with B.`;
    target.appendChild(compare);
  }

  byId('decrypt-note').textContent = both
    ? 'Both decryptions are shown for the same ciphertext.'
    : which === 'private'
      ? 'Now decrypt the same ciphertext with the public basis and compare.'
      : 'Now decrypt the same ciphertext with the private basis and compare.';
}
