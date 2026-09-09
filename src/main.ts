/**
 * Page wiring and state.
 *
 * RETIREMENT IS A CORRECTNESS RULE. Changing the dimension, the seed or the
 * error mode invalidates every verdict on the page, because they were all
 * computed from a key or a ciphertext that no longer exists. Every such change
 * therefore clears the ciphertext, the bound, and all three verdicts before
 * anything new is computed. Leaving a stale PASS on screen would be the page
 * lying about what it had just done, and it is also the one thing that makes the
 * end-to-end tests able to tell "recomputed" from "never changed".
 */

import './style.css';

import type { Ciphertext, GghKey, Mat } from './lattice/types';
import { gghKeygen, paperK, SIGMA } from './lattice/keygen';
import { inverse, makeRng } from './lattice/matrix';
import { encrypt, encryptNonCongruent, randomMessage } from './lattice/roundoff';
import { byId, retire } from './ui/dom';
import { renderAct1 } from './ui/act1';
import { clearDecryptResults, renderBound, renderCiphertext, runDecrypt } from './ui/act2';
import { clearBreak1, resetBreak1, stepBreak1 } from './ui/act3';
import { cancelBreak2, initBreak2, runBreak2InWorker } from './ui/act4';
import { renderAct5 } from './ui/act5';
import { clearHnfPanel, renderHnfPanel } from './ui/hnf-panel';
import { clearBaselinePanel, renderBaselinePanel } from './ui/baseline-panel';

/** Which error distribution the encryptor draws from. */
type ErrorMode = 'pm3' | 'one-bad' | 'uniform';

interface State {
  key: GghKey;
  /** The signature key for Act 4: GGH's own k, which is the right rule there. */
  sigKey: GghKey;
  Rinv: Mat;
  Binv: Mat;
  ct: Ciphertext | null;
  seed: number;
  mode: ErrorMode;
}

let state: State | null = null;

function readDim(): number {
  return Number(byId<HTMLInputElement>('dim-slider').value);
}
function readSeed(): number {
  return Number(byId<HTMLInputElement>('seed-input').value) || 1;
}
function readMode(): ErrorMode {
  return byId<HTMLSelectElement>('sigma-select').value as ErrorMode;
}

/**
 * Retire everything that depends on the ENCRYPTION experiment: the ciphertext,
 * the bound, the decryption results and Break 1.
 *
 * Deliberately does NOT touch Act 4. Break 2 attacks a different scheme with a
 * different key, and the error distribution is a property of GGH encryption
 * only, so cancelling a running descent because the encryption error mode
 * changed would be retiring a result that is still perfectly valid.
 */
function retireEncryptionExperiment(): void {
  byId('ciphertext-strip').innerHTML = '';
  byId('i2-bound').innerHTML = '';
  // Both persistent per-basis result cells go too, or a stale DECRYPTED would
  // survive a key change and be read as applying to the new ciphertext.
  clearDecryptResults();
  retire(byId('verdict-decrypt'), byId('verdict-break1'));
  clearBreak1();
  if (state) state.ct = null;
  byId<HTMLButtonElement>('btn-decrypt-private').disabled = true;
  byId<HTMLButtonElement>('btn-decrypt-public').disabled = true;
  // The verdict containers are left genuinely EMPTY, not filled with a "not run"
  // placeholder. Emptiness is what distinguishes "retired" from "still showing
  // the previous answer", so the guidance text lives in a sibling hint instead.
  byId('decrypt-note').textContent = 'Encrypt a message, then decrypt it with each basis.';
}

function keygen(): void {
  const n = readDim();
  const seed = readSeed();
  const mode = readMode();

  const key = gghKeygen(n, { rng: makeRng(seed) });
  // Act 4 keys separately, with GGH's own k. See the header of ui/act4.ts.
  const sigKey = gghKeygen(n, { rng: makeRng(seed ^ 0x516e), k: paperK(n) });

  state = {
    key,
    sigKey,
    Rinv: inverse(key.R),
    Binv: inverse(key.B),
    ct: null,
    seed,
    mode,
  };

  retireEncryptionExperiment();
  // A new key or dimension DOES invalidate Act 4 -- unlike the error mode, which
  // Act 4's scheme does not use at all.
  retire(byId('verdict-break2'));
  // Silent: the key this run belonged to is being replaced, so announcing
  // "cancelled" would describe a run the reader is no longer looking at.
  cancelBreak2(true);
  // The HNF exhibit is computed on demand rather than on every keygen: it is
  // BigInt work, ~68 ms at n=60, and most readers will not open it.
  clearHnfPanel();
  clearBaselinePanel();
  renderAct1(key);
  // The dimension is stamped on the proof so a re-key has a completion signal:
  // the four exact checks render identically for every key, so without this
  // there is nothing on the page that changes when a new key arrives.
  byId('i1-proof').dataset.n = String(n);

  byId('keygen-note').textContent =
    `Dimension ${n}, k = ${key.k}, noise half-width l = ${key.l}. ` +
    `${key.keygenAttempts} candidate key${key.keygenAttempts === 1 ? '' : 's'} drawn before one had ` +
    `a determinant coprime to 6 (only 12-17% do, and Break 1 needs it).`;

  initBreak2(sigKey, seed);
}

function doEncrypt(): void {
  if (!state) return;
  const { key } = state;
  const rng = makeRng(state.seed * 7 + 13);
  const m = randomMessage(key.n, rng);
  const ct =
    state.mode === 'pm3'
      ? encrypt(m, key.B, rng)
      : state.mode === 'uniform'
        ? encryptNonCongruent(m, key.B, rng, SIGMA)
        : encryptNonCongruent(m, key.B, rng, SIGMA, 1);
  state.ct = ct;

  renderCiphertext(ct);
  renderBound(ct, state.Rinv, state.Binv);
  byId<HTMLButtonElement>('btn-decrypt-private').disabled = false;
  byId<HTMLButtonElement>('btn-decrypt-public').disabled = false;
  retire(byId('verdict-decrypt'));
  byId('decrypt-note').textContent = 'Now decrypt with each basis and compare.';
  resetBreak1(ct, key, state.Binv);
}

function wire(): void {
  const dim = byId<HTMLInputElement>('dim-slider');
  const out = byId('dim-out');
  out.textContent = dim.value;

  dim.addEventListener('input', () => {
    out.textContent = dim.value;
  });
  dim.addEventListener('change', keygen);
  byId('seed-input').addEventListener('change', keygen);
  byId('sigma-select').addEventListener('change', () => {
    // No-op guard: only retire when the value actually CHANGED. A native select
    // fires no change event when a user re-picks the current option, but
    // scripted selection does, and "retire on any interaction" would otherwise
    // pass the retirement tests while being wrong.
    const next = readMode();
    if (state && state.mode === next) return;
    if (state) state.mode = next;
    retireEncryptionExperiment();
  });
  byId('btn-keygen').addEventListener('click', keygen);
  byId('btn-hnf').addEventListener('click', () => {
    if (state) renderHnfPanel(state.key);
  });
  byId('btn-baseline').addEventListener('click', () => {
    if (state) renderBaselinePanel(state.key, state.seed);
  });
  byId('btn-encrypt').addEventListener('click', doEncrypt);
  byId('btn-decrypt-private').addEventListener('click', () => {
    if (state?.ct) runDecrypt(state.ct, state.key, state.Rinv, state.Binv, 'private');
  });
  byId('btn-decrypt-public').addEventListener('click', () => {
    if (state?.ct) runDecrypt(state.ct, state.key, state.Rinv, state.Binv, 'public');
  });
  byId('btn-break1-step').addEventListener('click', () => {
    if (state) stepBreak1(state.key);
  });
  byId('btn-break1-reset').addEventListener('click', () => {
    if (state?.ct) resetBreak1(state.ct, state.key, state.Binv);
  });
  byId('btn-break2-run').addEventListener('click', () => {
    if (state) runBreak2InWorker(state.sigKey, state.seed, 'roundoff');
  });
  byId('btn-break2-gaussian').addEventListener('click', () => {
    if (state) runBreak2InWorker(state.sigKey, state.seed, 'klein');
  });
  // Wrapped, not passed directly: addEventListener would hand the MouseEvent to
  // cancelBreak2's `silent` parameter, which is truthy, and the CANCELLED status
  // would never be shown.
  byId('btn-break2-cancel').addEventListener('click', () => cancelBreak2());
}

function boot(): void {
  wire();
  renderAct5();
  keygen();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
