/**
 * Act 2 -- encrypt, then decrypt twice.
 *
 * The two decrypt buttons call the SAME function with a different basis. That is
 * deliberate: the asymmetry has to come from the basis, not from two different
 * code paths, or the exhibit would be staging its own conclusion.
 */

import type { Ciphertext, GghKey, Mat } from '../lattice/types';
import { decryptBound, latticePointToMessage, reEncryptionCheck, roundOff } from '../lattice/roundoff';
import { SIGMA } from '../lattice/keygen';
import { byId, fx, kvList, verdict } from './dom';

/** Which basis a decryption attempt used. */
export type BasisChoice = 'private' | 'public';

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
  const caption = document.createElement('p');
  caption.className = 'panel-hint';
  const allCongruent = Array.from(ct.e).every((x) => Math.abs(x) === sigma);
  caption.textContent = allCongruent
    ? `Top row is c = m*B + e; bottom row is e. Every entry is +-${sigma}, so every entry is congruent to ${sigma} mod ${2 * sigma}. That is the only thing Break 1 needs.`
    : `Top row is c = m*B + e; bottom row is e. Outlined coordinates are not +-${sigma}, so the mod-${2 * sigma} congruence Break 1 depends on no longer holds.`;
  strip.parentElement?.appendChild(caption);
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
  ]);
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

  const label = which === 'private' ? 'private basis R' : 'public basis B';
  const target = byId('verdict-decrypt');

  if (check.ok) {
    verdict(
      target,
      'ok',
      'DECRYPTED',
      `Round-off with the ${label} recovered the message. Verified by re-encryption: ` +
        `c minus m*B is a legal error vector with every entry +-${SIGMA}. ` +
        `The deciding number was ${fx(bound.actual)}, under the 0.5 threshold.`,
    );
  } else {
    let wrongCoords = 0;
    for (let i = 0; i < recovered.length; i++) if (recovered[i] !== ct.m[i]) wrongCoords++;
    verdict(
      target,
      'bad',
      'WRONG MESSAGE',
      `Round-off with the ${label} landed on a different lattice point. ` +
        `Re-encryption rejects it: c minus m*B is not a legal error vector. ` +
        `${wrongCoords} of ${recovered.length} coordinates are wrong. ` +
        `The deciding number was ${fx(bound.actual)}, over the 0.5 threshold. ` +
        `Same algorithm, same ciphertext -- only the basis changed.`,
    );
  }
}
