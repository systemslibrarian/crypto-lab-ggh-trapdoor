/**
 * Act 5 -- why modern schemes look different.
 *
 * Every factual claim in this panel was checked against a primary source before
 * it was written: the GGH, Nguyen, Nguyen-Regev, Babai and Micciancio papers,
 * the Falcon specification, and FIPS 203. Where a source could not be reached,
 * the panel says so rather than asserting.
 *
 * Three corrections were made here after that check, and they are recorded
 * because the obvious summary of this lab is wrong in all three ways:
 *
 *  1. Nguyen 1999 does NOT attack the trapdoor's shape. It attacks the shape of
 *     the ENCRYPTION error vector; the private basis is never recovered and
 *     never needed. Only Nguyen-Regev attacks the trapdoor itself.
 *  2. "Not lattice hardness" overstates it. Nguyen reduced GGH to an EASIER
 *     lattice problem which he then still had to solve with lattice reduction,
 *     and it failed in dimension 400 because the residual problem stayed hard.
 *     His own section 7 says the error-vs-lattice-vector gap is "inherent to
 *     the GGH construction".
 *  3. The two breaks hit two DIFFERENT schemes: Nguyen broke GGH encryption,
 *     Nguyen-Regev broke the GGH signature design (and NTRUSign). There is no
 *     GGH signature challenge; Nguyen-Regev simulated one.
 */

import { byId } from './dom';

interface Card {
  title: string;
  body: string[];
}

const CARDS: Card[] = [
  {
    title: 'What actually went wrong',
    body: [
      'Neither break solved a hard lattice problem head-on. Both exploited the shape of ' +
        "GGH's own randomness.",
      'Nguyen 1999 broke GGH <em>encryption</em>. Because every entry of <code>e</code> is ' +
        '<code>&plusmn;&sigma;</code>, <code>e + s</code> vanishes mod <code>2&sigma;</code>, ' +
        'which leaks <code>m mod 2&sigma;</code> and shrinks the residual error from ' +
        '<code>&sigma;&radic;n</code> to <code>&radic;(n/4)</code>. Ordinary lattice reduction ' +
        'then finished four of the five published challenges. Dimension 400 held out until 2010.',
      'Nguyen&ndash;Regev 2006 broke the GGH <em>signature</em> design, and NTRUSign with it. ' +
        'Every deterministic Babai signature is a uniform sample from the secret ' +
        'parallelepiped, and a fourth-moment gradient descent recovers the secret basis up to ' +
        'sign and order.',
      'The first attack is about the error. The second is about the trapdoor. They are not the ' +
        'same lesson, and they are not attacks on the same scheme.',
    ],
  },
  {
    title: 'Falcon: sample, do not round',
    body: [
      'Falcon signs with the GPV framework over NTRU lattices, using fast Fourier sampling. ' +
        'Its own specification puts the lineage plainly: Klein 2000 randomised Babai&rsquo;s ' +
        'nearest-plane algorithm, Gentry&ndash;Peikert&ndash;Vaikuntanathan 2008 built the ' +
        'framework, Peikert 2010 gave a randomised round-off, and Ducas&ndash;Prest 2016 ' +
        'supplied the sampler Falcon actually uses.',
      'The output is a <em>spherical</em> Gaussian over the shifted lattice, with width ' +
        '<code>&sigma; &le; 1.312&middot;||B||<sub>GS</sub></code>. A sphere has no corners, so ' +
        'there is no parallelepiped to learn &mdash; run Act 4 with Gaussian signatures and ' +
        'watch the fourth moment sit flat at <code>1/48</code>.',
      'Falcon&rsquo;s specification is explicit that this is not incidental: for every known ' +
        'sampler, setting the width to zero &mdash; that is, signing deterministically &mdash; ' +
        '"opens the door to learning attacks" of exactly this kind.',
    ],
  },
  {
    title: 'ML-KEM: shape the error on purpose',
    body: [
      'FIPS 203 draws every secret and error coefficient from a centered binomial ' +
        'distribution, sampled by <code>SamplePolyCBD</code> as a difference of two sums of ' +
        '&eta; bits. The parameters are <code>&eta;<sub>1</sub></code> and ' +
        '<code>&eta;<sub>2</sub></code>: ML-KEM-512 uses 3 and 2, ML-KEM-768 and ML-KEM-1024 ' +
        'use 2 and 2.',
      'Nothing there has constant magnitude. The mod-2&sigma; observation that ended GGH ' +
        'encryption has no analogue, because there is no single modulus in which every error ' +
        'coefficient is congruent to the same thing.',
    ],
  },
  {
    title: 'Three different things are called GGH',
    body: [
      'The 1997 cryptosystem on this page is Goldreich, Goldwasser and Halevi.',
      'GGH13, the candidate multilinear maps from ideal lattices, is Garg, Gentry and Halevi ' +
        '(EUROCRYPT 2013). GGH15, graph-induced multilinear maps, is Gentry, Gorbunov and ' +
        'Halevi (TCC 2015).',
      'They are different constructions solving different problems &mdash; but they are not by ' +
        'different people. Shai Halevi is an author of all three.',
    ],
  },
];

const SCOPE: string[] = [
  'This lab runs at dimensions 8&ndash;60 so everything finishes in a browser tab. GGH was ' +
    'proposed at 200&ndash;400, and the published challenges were at exactly those sizes.',
  'It uses a larger diagonal shift <code>k</code> than the 1997 paper does. With the ' +
    "paper's own rule <code>k = 4&middot;&lceil;&radic;n&rceil;</code> and <code>&sigma; = 3</code>, " +
    'the legitimate owner fails to decrypt 56&ndash;57% of the time at n=8, because &sigma; in the ' +
    'paper is derived from the basis and only lands near 3 at the paper&rsquo;s own dimensions of ' +
    '200&ndash;400. <code>&sigma; = 3</code> is kept because <code>2&sigma; = 6</code> is what ' +
    'Break 1 runs in.',
  'LLL here is real and runs in the browser. BKZ is not implemented; Nguyen needed BKZ-20 and ' +
    'pruned BKZ-60 for the large challenges.',
  'NTRUSign is not built. It fell to the same Nguyen&ndash;Regev descent as Act 4 &mdash; that ' +
    'was the attack&rsquo;s real-world scalp, at 400 signatures without perturbation.',
  'Not production cryptography, and not a claim about lattice cryptography in general. ' +
    'GGH is broken; ML-KEM and Falcon are not, and the reasons they are shaped as they are ' +
    'sit directly above.',
];

const CITATIONS: Array<{ text: string; note?: string }> = [
  {
    text:
      'Goldreich, Goldwasser, Halevi. "Public-Key Cryptosystems from Lattice Reduction ' +
      'Problems." CRYPTO 1997, LNCS 1294, pp. 112-131.',
  },
  {
    text:
      'Nguyen. "Cryptanalysis of the Goldreich-Goldwasser-Halevi Cryptosystem from Crypto \'97." ' +
      'CRYPTO 1999, LNCS 1666, pp. 288-304.',
  },
  {
    text:
      'Nguyen, Regev. "Learning a Parallelepiped: Cryptanalysis of GGH and NTRU Signatures." ' +
      'EUROCRYPT 2006, LNCS 4004, pp. 271-288; Journal of Cryptology 22(2):139-160, 2009.',
  },
  {
    text:
      "Babai. \"On Lovasz' lattice reduction and the nearest lattice point problem.\" " +
      'Combinatorica 6(1):1-13, 1986.',
    note:
      'Both round-off and nearest-plane come from this one paper. The full text is paywalled; ' +
      'that attribution is taken from GGH\'s own citation of it and from the published abstract.',
  },
  {
    text:
      'Micciancio. "Improving Lattice Based Cryptosystems Using the Hermite Normal Form." ' +
      'CaLC 2001, LNCS 2146, pp. 126-145.',
  },
];

export function renderAct5(): void {
  const root = byId('act-5-body');
  root.innerHTML = '';

  const grid = document.createElement('div');
  grid.className = 'compare-grid';
  for (const card of CARDS) {
    const panel = document.createElement('div');
    panel.className = 'panel';
    const h = document.createElement('h3');
    h.textContent = card.title;
    panel.appendChild(h);
    for (const para of card.body) {
      const p = document.createElement('p');
      p.innerHTML = para;
      panel.appendChild(p);
    }
    grid.appendChild(panel);
  }
  root.appendChild(grid);

  const scope = document.createElement('div');
  scope.className = 'panel';
  const sh = document.createElement('h3');
  sh.textContent = 'What this lab does not do';
  scope.appendChild(sh);
  const ul = document.createElement('ul');
  for (const item of SCOPE) {
    const li = document.createElement('li');
    li.innerHTML = item;
    ul.appendChild(li);
  }
  scope.appendChild(ul);
  root.appendChild(scope);

  const cites = document.createElement('details');
  cites.className = 'panel';
  cites.id = 'sources';
  const ch = document.createElement('summary');
  ch.textContent = 'Sources: the five papers this lab is built from';
  cites.appendChild(ch);
  const ol = document.createElement('ul');
  for (const c of CITATIONS) {
    const li = document.createElement('li');
    li.textContent = c.text;
    if (c.note) {
      const small = document.createElement('span');
      small.className = 'step-detail';
      small.textContent = c.note;
      li.appendChild(small);
    }
    ol.appendChild(li);
  }
  cites.appendChild(ol);
  root.appendChild(cites);
}
