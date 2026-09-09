#!/usr/bin/env node
/**
 * `npm run evidence` -- regenerate every measured number in this repo from the
 * real modules, with fixed seeds, into one machine-readable artifact.
 *
 * WHY THIS EXISTS. The README carries a table of impressive measured numbers and
 * the source carries dozens more inside comments. Hand-maintained prose drifts:
 * a constant gets tuned, the sentence describing it does not, and six months
 * later nobody can tell which of the two is the lie. Everything printed here is
 * recomputed from `src/` on every run, so a number in the README is either
 * reproducible by `node scripts/evidence.mjs` or it is not a measurement.
 *
 * HOW IT LOADS TYPESCRIPT, and why this way. The repo is ESM and the modules are
 * `.ts` with extensionless specifiers (`import { rnd } from './matrix'`). Node
 * cannot import those directly: its own type stripping requires full specifiers,
 * so `./matrix` would not resolve even on Node 26. Three options were available.
 *
 *   - esbuild or tsx: NEITHER IS PRESENT. Vite 8 in this repo is the rolldown
 *     build, so `node_modules/esbuild` does not exist and `import('esbuild')`
 *     throws; tsx is not a dependency either, and adding one to generate
 *     evidence would be a new supply-chain edge for no capability.
 *   - a vitest run that writes the JSON: works, but needs a second entry file
 *     inside `src/` plus a bespoke config, and buries the artifact behind a test
 *     runner whose reporter owns stdout.
 *   - vite's own `build()` in SSR mode: one call, ~70 ms measured, uses the
 *     SAME toolchain and resolver that builds the shipped bundle, and vite is
 *     already a declared devDependency. No new dependency, no new config file.
 *
 * The third is what runs below: a generated entry re-exports the modules under
 * test, vite bundles it to a temp `.mjs`, and this script imports that. The
 * temp directory is removed in a `finally`, so a crash leaves nothing behind.
 *
 * DETERMINISM. Every seed is a literal in `SEEDS` below and is copied into the
 * artifact's provenance block, so a reader can re-derive any row. The only
 * machine-dependent values are the wall-clock timings (`msP50`, `msP95`, `ms`,
 * `lllMs`, `proofMs`) and the bundle sizes; provenance.note says so, and the
 * machine they were measured on is recorded beside them.
 *
 * Usage:
 *   node scripts/evidence.mjs [--out <path>] [--timestamp <iso>] [--quiet]
 *
 * The timestamp may also come from EVIDENCE_TIMESTAMP or SOURCE_DATE_EPOCH, so
 * CI can pin it and get a byte-identical artifact apart from the timings.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Every seed this artifact depends on, in one place.
 *
 * These are copied verbatim into `provenance.seedCorpus`: a number in the
 * artifact that cannot be traced back to one of these is not reproducible, and
 * that would be a bug in this script.
 */
const SEEDS = {
  i1: { keySeedBase: 1000, keys: 3 },
  i2: { keySeedBase: 7000, ciphertextSeedBase: 7500, ciphertexts: 40 },
  keygen: { seedBase: 20000 },
  baseline: { keySeedBase: 31000, ciphertextSeedBase: 31500, ciphertexts: 25 },
  break1: { keySeedBase: 41000, ciphertextSeedBase: 41500, honest: 20, tampered: 10 },
  break2: {
    roundOffKeySeeds: [20260908, 555001, 555002, 555003],
    kleinKeySeeds: [9090, 9091],
    attackSeed: 4242,
    startN: 4000,
    capN: 32000,
    forgeries: 20,
  },
  hnf: { keySeedBase: 51000 },
};

/** Dimensions the lab ships, and the ones every by-dimension table is keyed on. */
const DIMS = [8, 16, 32, 60];

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = { out: path.join(ROOT, 'evidence', 'baseline.json'), timestamp: null, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') out.out = path.resolve(argv[++i] ?? '');
    else if (a === '--timestamp') out.timestamp = argv[++i] ?? null;
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--help' || a === '-h') {
      process.stdout.write(
        'usage: node scripts/evidence.mjs [--out <path>] [--timestamp <iso>] [--quiet]\n',
      );
      process.exit(0);
    } else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

/**
 * The artifact timestamp.
 *
 * Taken from the flag, then EVIDENCE_TIMESTAMP, then SOURCE_DATE_EPOCH (the
 * reproducible-builds convention, seconds since the epoch), and only then from
 * the clock. Pinning it is what lets CI diff two artifacts and see only the
 * numbers change.
 */
function resolveTimestamp(flag) {
  if (flag) return new Date(flag).toISOString();
  if (process.env.EVIDENCE_TIMESTAMP) return new Date(process.env.EVIDENCE_TIMESTAMP).toISOString();
  if (process.env.SOURCE_DATE_EPOCH) {
    return new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString();
  }
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// small numeric helpers -- kept here rather than imported, because this file
// must keep running even if src/ is mid-edit by another agent.
// ---------------------------------------------------------------------------

/** Round for the artifact. Six decimals is far more than any claim here uses. */
const r6 = (x) => (Number.isFinite(x) ? Math.round(x * 1e6) / 1e6 : x === null ? null : String(x));
/** Round a millisecond timing. Sub-microsecond digits are noise. */
const r3 = (x) => (Number.isFinite(x) ? Math.round(x * 1e3) / 1e3 : null);

/**
 * Nearest-rank percentile: the smallest observed value at or above the rank.
 *
 * Nearest-rank rather than interpolated because every timing list here is short
 * (10-40 samples) and an interpolated p95 of 20 samples reports a number that
 * was never measured.
 */
function pct(xs, p) {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1));
  return s[idx];
}

const min = (xs) => (xs.length ? Math.min(...xs) : null);
const max = (xs) => (xs.length ? Math.max(...xs) : null);

// ---------------------------------------------------------------------------
// loading src/*.ts through vite's SSR build
// ---------------------------------------------------------------------------

/**
 * Modules the evidence needs, as `<name>: <path under src/>`.
 *
 * `baseline` is OPTIONAL: it is re-exported only when the file is present, so
 * this script still runs against a checkout from before audit finding 1 landed.
 * Every other entry is required, and a missing one is a build error on purpose.
 */
const OPTIONAL_MODULES = new Set(['baseline']);

const MODULES = {
  matrix: 'lattice/matrix.ts',
  keygen: 'lattice/keygen.ts',
  roundoff: 'lattice/roundoff.ts',
  invariants: 'lattice/invariants.ts',
  hnf: 'lattice/hnf.ts',
  lll: 'attack/lll.ts',
  break1: 'attack/break1.ts',
  break2: 'attack/break2.ts',
  baseline: 'attack/baseline.ts',
  sign: 'sign/sign.ts',
  klein: 'sign/klein.ts',
  verify: 'sign/verify.ts',
};

async function loadModules(tmpDir) {
  const entry = path.join(tmpDir, 'evidence-entry.ts');
  const lines = [];
  for (const [name, rel] of Object.entries(MODULES)) {
    const abs = path.join(ROOT, 'src', rel);
    if (OPTIONAL_MODULES.has(name) && !fs.existsSync(abs)) continue;
    lines.push(`export * as ${name} from ${JSON.stringify(abs)};`);
  }
  fs.writeFileSync(entry, lines.join('\n') + '\n');

  const { build } = await import('vite');
  await build({
    root: ROOT,
    configFile: false, // the repo config sets `base` for Pages; irrelevant and noisy here.
    logLevel: 'error',
    build: {
      ssr: entry,
      outDir: tmpDir,
      emptyOutDir: false,
      minify: false,
      write: true,
      target: 'node22',
      rollupOptions: { output: { entryFileNames: 'evidence-bundle.mjs', format: 'es' } },
    },
  });
  return import(path.join(tmpDir, 'evidence-bundle.mjs'));
}

// ---------------------------------------------------------------------------
// provenance
// ---------------------------------------------------------------------------

function git(args, fallback) {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return fallback;
  }
}

function provenance(timestamp) {
  return {
    timestamp,
    commit: git(['rev-parse', 'HEAD'], 'unknown'),
    commitShort: git(['rev-parse', '--short', 'HEAD'], 'unknown'),
    branch: git(['rev-parse', '--abbrev-ref', 'HEAD'], 'unknown'),
    // A dirty tree is not an error -- this runs during development -- but an
    // artifact generated from uncommitted work must say so, or the commit sha
    // above is a false provenance.
    treeClean: git(['status', '--porcelain'], 'unknown') === '',
    node: process.version,
    v8: process.versions.v8,
    os: `${os.type()} ${os.release()}`,
    platform: process.platform,
    arch: process.arch,
    cpuModel: os.cpus()?.[0]?.model ?? 'unknown',
    seedCorpus: SEEDS,
    dimensions: DIMS,
    generator: 'scripts/evidence.mjs',
    note:
      'Every value here is recomputed from src/ with the seeds above. Wall-clock ' +
      'fields (msP50/msP95/ms) and bundle sizes are the only machine-dependent ones.',
  };
}

// ---------------------------------------------------------------------------
// I1 -- same-lattice proof, and the headroom under 2^53
// ---------------------------------------------------------------------------

function sectionI1(m) {
  const { gghKeygen } = m.keygen;
  const { proveSameLattice } = m.invariants;
  const { makeRng, TWO53 } = m.matrix;

  const byDimension = DIMS.map((n) => {
    let allPass = true;
    let maxIntermediate = 0;
    const msList = [];
    for (let s = 0; s < SEEDS.i1.keys; s++) {
      const key = gghKeygen(n, { rng: makeRng(SEEDS.i1.keySeedBase * n + s) });
      const stats = { maxIntermediate: 0 };
      const t0 = performance.now();
      const proof = proveSameLattice(key.R, key.B, { stats });
      msList.push(performance.now() - t0);
      if (!proof.ok) allPass = false;
      if (stats.maxIntermediate > maxIntermediate) maxIntermediate = stats.maxIntermediate;
    }
    return {
      n,
      keys: SEEDS.i1.keys,
      allPass,
      maxIntermediate,
      two53: TWO53,
      // The headroom IS the claim: integer exactness in doubles is safe only
      // while this stays large, so it is measured rather than asserted.
      headroom: r6(TWO53 / maxIntermediate),
      spareBits: r6(Math.log2(TWO53 / maxIntermediate)),
      msP50: r3(pct(msList, 0.5)),
    };
  });
  return {
    claim: 'C1 / invariant I1: U*R = B, V*B = R and U*V = I, all in exact integers under 2^53.',
    ok: byDimension.every((d) => d.allPass),
    byDimension,
  };
}

// ---------------------------------------------------------------------------
// I2 -- the decryption bound, actual and worst case, and the iff
// ---------------------------------------------------------------------------

function sectionI2(m) {
  const { gghKeygen, SIGMA } = m.keygen;
  const { decryptBound, encrypt, randomMessage, roundOff, worstCaseBound } = m.roundoff;
  const { inverse, makeRng, vecMat } = m.matrix;

  const byDimension = DIMS.map((n) => {
    const key = gghKeygen(n, { rng: makeRng(SEEDS.i2.keySeedBase + n) });
    const Rinv = inverse(key.R);
    const Binv = inverse(key.B);
    const rng = makeRng(SEEDS.i2.ciphertextSeedBase + n);
    const priv = [];
    const pub = [];
    // The number that matters: how often `predictsSuccess` disagreed with what
    // round-off actually did. I2 claims an exact iff, so anything but 0 is a
    // falsified claim, not a tolerance to be widened.
    let iffMismatches = 0;
    let privDecrypted = 0;
    let pubDecrypted = 0;
    for (let t = 0; t < SEEDS.i2.ciphertexts; t++) {
      const msg = randomMessage(n, rng);
      const { c, e } = encrypt(msg, key.B, rng);
      const truePoint = vecMat(msg, key.B);
      for (const [basis, basisInv, sink] of [
        [key.R, Rinv, priv],
        [key.B, Binv, pub],
      ]) {
        const bound = decryptBound(e, basisInv, SIGMA);
        const got = roundOff(c, basis, basisInv);
        let exact = true;
        for (let i = 0; i < n; i++) if (got[i] !== truePoint[i]) exact = false;
        if (bound.predictsSuccess !== exact) iffMismatches++;
        if (exact) sink === priv ? privDecrypted++ : pubDecrypted++;
        sink.push(bound.actual);
      }
    }
    const worstPriv = worstCaseBound(Rinv, SIGMA);
    const worstPub = worstCaseBound(Binv, SIGMA);
    return {
      n,
      ciphertexts: SEEDS.i2.ciphertexts,
      iffMismatches,
      privateBasis: {
        actualMin: r6(min(priv)),
        actualMedian: r6(pct(priv, 0.5)),
        actualMax: r6(max(priv)),
        worstCase: r6(worstPriv),
        // worstCase is the max over EVERY error in {+-sigma}^n, so below 1/2
        // means decryption provably cannot fail -- not "did not fail here".
        guaranteed: worstPriv < 0.5,
        guaranteeMargin: r6(0.5 / worstPriv),
        decryptedCorrectly: privDecrypted,
      },
      publicBasis: {
        actualMin: r6(min(pub)),
        actualMedian: r6(pct(pub, 0.5)),
        actualMax: r6(max(pub)),
        worstCase: r6(worstPub),
        guaranteed: worstPub < 0.5,
        overThreshold: r6(pct(pub, 0.5) / 0.5),
        decryptedCorrectly: pubDecrypted,
      },
    };
  });

  return {
    claim:
      'C2 / invariant I2: Babai round-off recovers the lattice point iff ' +
      'max|e*basis^-1| < 1/2, and the private basis carries a worst-case guarantee.',
    sigma: m.keygen.SIGMA,
    ok:
      byDimension.every((d) => d.iffMismatches === 0) &&
      byDimension.every((d) => d.privateBasis.guaranteed),
    byDimension,
  };
}

// ---------------------------------------------------------------------------
// keygen -- the mod-6 acceptance rate
// ---------------------------------------------------------------------------

/**
 * Acceptance rate from the geometric draw counter keygen already reports.
 *
 * `keygenAttempts` is the number of candidate R drawn until one had det coprime
 * to 6, so keys/sum(attempts) is the maximum-likelihood estimate of the
 * acceptance probability. Counting draws this way costs nothing extra and uses
 * the shipped code path rather than a re-implementation of the R distribution.
 */
function sectionKeygen(m) {
  const { gghKeygen } = m.keygen;
  const { makeRng } = m.matrix;
  // Fewer keys at the top end on purpose: n=60 keygen is O(n^3) per draw and 40
  // keys already pins the rate to within a couple of points, which is all the
  // README's "12-17%" needs.
  const plan = { 8: 200, 16: 150, 32: 80, 60: 40 };
  const byDimension = DIMS.map((n) => {
    const keys = plan[n];
    let attempts = 0;
    for (let s = 0; s < keys; s++) {
      attempts += gghKeygen(n, { rng: makeRng(SEEDS.keygen.seedBase + n * 1000 + s) }).keygenAttempts;
    }
    return {
      n,
      keys,
      candidateDraws: attempts,
      acceptanceRate: r6(keys / attempts),
      meanDrawsToAccept: r6(attempts / keys),
    };
  });
  const all = byDimension.reduce(
    (a, d) => ({ keys: a.keys + d.keys, draws: a.draws + d.candidateDraws }),
    { keys: 0, draws: 0 },
  );
  return {
    claim:
      'Only keys whose det is coprime to 6 are usable by Break 1, so keygen resamples; ' +
      'this is the measured fraction of random R that qualify.',
    overallAcceptanceRate: r6(all.keys / all.draws),
    byDimension,
  };
}

// ---------------------------------------------------------------------------
// baseline -- what an ordinary attacker gets with B, with LLL(B), and with R
// ---------------------------------------------------------------------------

/**
 * The public-LLL baseline: three decryption outcomes over one key per dimension.
 *
 * The LLL(B) row is delegated to `src/attack/baseline.ts`
 * (`runPublicLllBaseline`), which is the shipped implementation of audit finding
 * 1 and whose verdict is attacker-side: it confirms every recovery with the
 * public re-encryption check rather than by comparing with the message. Two
 * implementations of one measurement is exactly the drift this pipeline exists
 * to stop, so nothing here re-derives it.
 *
 * TODO(baseline): the inline fallback below exists only so this script still
 * runs against a checkout from before that module landed. Delete it once the
 * repository history no longer matters.
 *
 * The raw-B and secret-R rows ARE computed here, because they are not the
 * baseline attack -- they are the shipped decryptor run with each basis in turn,
 * over one shared ciphertext stream so the two share the same error vectors.
 * The LLL row draws its own ciphertexts inside the module; same key, same
 * distribution, independent draws, and the artifact says so.
 */
function sectionBaseline(m, warn) {
  const { gghKeygen, SIGMA } = m.keygen;
  const { decryptBound, encrypt, latticePointToMessage, randomMessage, reEncryptionCheck, roundOff } =
    m.roundoff;
  const { inverse, log10OrthogonalityDefect, makeRng } = m.matrix;
  const { lllReduce, shortestRowNorm } = m.lll;
  const { matchUpToSignPerm } = m.break2;

  const runBaseline = m.baseline?.runPublicLllBaseline;
  if (typeof runBaseline !== 'function') {
    warn(
      'src/attack/baseline.ts is absent (or does not export runPublicLllBaseline): ' +
        'the LLL(B) row is computed inline from lllReduce -- see TODO(baseline).',
    );
  }

  const byDimension = DIMS.map((n) => {
    const key = gghKeygen(n, { rng: makeRng(SEEDS.baseline.keySeedBase + n) });
    const Rinv = inverse(key.R);
    const Binv = inverse(key.B);
    const trials = SEEDS.baseline.ciphertexts;

    // Rows 1 and 3: the shipped decryptor with the public basis and with the
    // trapdoor, over ONE ciphertext stream so both see the same error vectors.
    const rng = makeRng(SEEDS.baseline.ciphertextSeedBase + n);
    const counts = { raw: 0, secret: 0 };
    const bounds = { raw: [], secret: [] };
    // Cross-check: the public re-encryption check must agree with the exact
    // message comparison on every ciphertext. It has no business disagreeing,
    // and a non-zero count here would mean one of the two is lying.
    let reEncryptionDisagreements = 0;
    for (let t = 0; t < trials; t++) {
      const msg = randomMessage(n, rng);
      const { c, e } = encrypt(msg, key.B, rng, SIGMA);
      for (const [name, basis, basisInv] of [
        ['raw', key.B, Binv],
        ['secret', key.R, Rinv],
      ]) {
        bounds[name].push(decryptBound(e, basisInv, SIGMA).actual);
        const got = latticePointToMessage(roundOff(c, basis, basisInv), Binv);
        let exact = true;
        for (let i = 0; i < n; i++) if (got[i] !== msg[i]) exact = false;
        if (exact) counts[name]++;
        if (reEncryptionCheck(c, got, key.B, SIGMA).ok !== exact) reEncryptionDisagreements++;
      }
    }

    // Row 2: the baseline attack itself.
    let lll;
    if (typeof runBaseline === 'function') {
      const res = runBaseline(key, {
        rng: makeRng(SEEDS.baseline.ciphertextSeedBase + n + 1),
        ciphertexts: trials,
        sigma: SIGMA,
        Binv,
      });
      lll = {
        source: 'src/attack/baseline.ts',
        decrypted: res.decrypted,
        trials: res.attempted,
        successRate: res.attempted ? r6(res.decrypted / res.attempted) : null,
        // Attacker-computable: the worst case over EVERY error in {+-sigma}^n,
        // measured from the reduced basis alone. Below 1/2 means the reduced
        // PUBLIC basis carries the same decryption guarantee the trapdoor does.
        worstCaseBound: r6(res.worstCaseBound),
        guaranteed: res.guaranteed,
        log10OrthogonalityDefect: r6(res.log10DefectReduced),
        shortestRowNorm: r6(shortestRowNorm(res.reducedBasis)),
        lllMs: r3(res.ms),
        lllSwaps: res.swaps,
        lllIters: res.iters,
        lllGuardMax: res.guardMax,
        lllFailure: res.failure ? res.failure.kind : null,
        // LAB-ONLY GROUND TRUTH, and the whole reason this section exists: at
        // every dimension this lab offers, LLL on the PUBLIC basis returns the
        // private basis itself, up to sign and permutation -- entrywise integer
        // equality, no tolerance. The baseline does not merely "sometimes
        // decrypt": it recovers the trapdoor. Any page copy implying the public
        // basis hides R from off-the-shelf reduction at n <= 60 is contradicted
        // by this row.
        matchesSecretUpToSignPerm: res.matchesSecret,
        rowsMatchingSecret: res.matchedRows,
        attackerVerdictOk: res.ok,
      };
    } else {
      const t0 = performance.now();
      const red = lllReduce(key.B);
      const ms = performance.now() - t0;
      const L = red.basis;
      const Linv = inverse(L);
      const inlineRng = makeRng(SEEDS.baseline.ciphertextSeedBase + n + 1);
      let decrypted = 0;
      for (let t = 0; t < trials; t++) {
        const msg = randomMessage(n, inlineRng);
        const ct = encrypt(msg, key.B, inlineRng, SIGMA);
        const got = latticePointToMessage(roundOff(ct.c, L, Linv), Binv);
        if (reEncryptionCheck(ct.c, got, key.B, SIGMA).ok) decrypted++;
      }
      const match = matchUpToSignPerm(L, key.R);
      lll = {
        source: 'inline (src/attack/baseline.ts absent)',
        decrypted,
        trials,
        successRate: r6(decrypted / trials),
        worstCaseBound: r6(m.roundoff.worstCaseBound(Linv, SIGMA)),
        guaranteed: m.roundoff.worstCaseBound(Linv, SIGMA) < 0.5,
        log10OrthogonalityDefect: r6(log10OrthogonalityDefect(L)),
        shortestRowNorm: r6(shortestRowNorm(L)),
        lllMs: r3(ms),
        lllSwaps: red.swaps,
        lllIters: red.iters,
        lllGuardMax: red.guardMax,
        lllFailure: red.failure ? red.failure.kind : null,
        matchesSecretUpToSignPerm: match.complete,
        rowsMatchingSecret: match.matched,
        attackerVerdictOk: red.failure === null && decrypted === trials,
      };
    }

    const row = (name, extra) => ({
      decrypted: counts[name],
      trials,
      successRate: r6(counts[name] / trials),
      medianI2: r6(pct(bounds[name], 0.5)),
      ...extra,
    });

    return {
      n,
      reEncryptionDisagreements,
      rawB: row('raw', {
        worstCaseBound: r6(m.roundoff.worstCaseBound(Binv, SIGMA)),
        guaranteed: m.roundoff.worstCaseBound(Binv, SIGMA) < 0.5,
        log10OrthogonalityDefect: r6(log10OrthogonalityDefect(key.B)),
        shortestRowNorm: r6(shortestRowNorm(key.B)),
      }),
      lllB: lll,
      secretR: row('secret', {
        worstCaseBound: r6(m.roundoff.worstCaseBound(Rinv, SIGMA)),
        guaranteed: m.roundoff.worstCaseBound(Rinv, SIGMA) < 0.5,
        log10OrthogonalityDefect: r6(log10OrthogonalityDefect(key.R)),
        shortestRowNorm: r6(shortestRowNorm(key.R)),
      }),
    };
  });

  return {
    claim:
      'Raw Babai round-off with B fails; LLL(B) -- the ordinary public attack -- ' +
      'recovers the private basis up to sign and permutation at every dimension ' +
      'this lab offers, and decrypts as well as the trapdoor does.',
    source: byDimension[0]?.lllB.source ?? 'unknown',
    note:
      'raw-B and secret-R share one ciphertext stream; the LLL(B) row draws its own ' +
      'inside src/attack/baseline.ts, on the same key.',
    ok: byDimension.every((d) => d.reEncryptionDisagreements === 0),
    byDimension,
  };
}

// ---------------------------------------------------------------------------
// Break 1 -- Nguyen's attack, with its negative control
// ---------------------------------------------------------------------------

function sectionBreak1(m) {
  const { gghKeygen } = m.keygen;
  const { encrypt, encryptNonCongruent, randomMessage } = m.roundoff;
  const { inverse, makeRng } = m.matrix;
  const { runBreak1 } = m.break1;

  const byDimension = DIMS.map((n) => {
    const key = gghKeygen(n, { rng: makeRng(SEEDS.break1.keySeedBase + n) });
    const Binv = inverse(key.B);
    const rng = makeRng(SEEDS.break1.ciphertextSeedBase + n);

    const honestMs = [];
    const honestRatios = [];
    let honestVerified = 0;
    for (let t = 0; t < SEEDS.break1.honest; t++) {
      const msg = randomMessage(n, rng);
      const { c } = encrypt(msg, key.B, rng);
      const t0 = performance.now();
      const res = runBreak1(c, key.B, { Binv });
      honestMs.push(performance.now() - t0);
      if (res.verified) honestVerified++;
      honestRatios.push(res.observables.normRatio);
    }

    // The negative control: a non-congruent error breaks the mod-2sigma step, so
    // the attack must FAIL and must say why. The separation below is the number
    // the lab shows on screen, so it has to come from a real run.
    const tamperedRatios = [];
    let tamperedVerified = 0;
    let tamperedDivisionExact = 0;
    for (let t = 0; t < SEEDS.break1.tampered; t++) {
      const msg = randomMessage(n, rng);
      const { c } = encryptNonCongruent(msg, key.B, rng);
      const res = runBreak1(c, key.B, { Binv });
      if (res.verified) tamperedVerified++;
      if (res.observables.divisionExact) tamperedDivisionExact++;
      tamperedRatios.push(res.observables.normRatio);
    }

    return {
      n,
      honest: {
        trials: SEEDS.break1.honest,
        verified: honestVerified,
        successRate: r6(honestVerified / SEEDS.break1.honest),
        msP50: r3(pct(honestMs, 0.5)),
        msP95: r3(pct(honestMs, 0.95)),
        normRatioMin: r6(min(honestRatios)),
        normRatioMax: r6(max(honestRatios)),
      },
      tampered: {
        trials: SEEDS.break1.tampered,
        verified: tamperedVerified,
        // Measured 100% in this repo's own comments: the intuitive story that
        // the division by 6 comes out fractional is WRONG, and the artifact has
        // to keep saying so.
        divisionStillExact: tamperedDivisionExact,
        normRatioMin: r6(min(tamperedRatios)),
        normRatioMax: r6(max(tamperedRatios)),
      },
      // The discriminator, as one number: how far apart the two populations are.
      // Anything at or below 1 would mean the negative control is not separated.
      separation: r6(min(tamperedRatios) / max(honestRatios)),
    };
  });

  return {
    claim:
      'C3: Nguyen mod-2sigma + LLL recovers the message with the public key only, ' +
      'verified by re-encryption (I5). C4: a non-congruent error kills it.',
    ok:
      byDimension.every((d) => d.honest.verified === d.honest.trials) &&
      byDimension.every((d) => d.tampered.verified === 0) &&
      byDimension.every((d) => d.separation > 1),
    byDimension,
  };
}

// ---------------------------------------------------------------------------
// Break 2 -- the parallelepiped learner, and the Gaussian defence
// ---------------------------------------------------------------------------

/**
 * Break 2 evidence at n=8 with the PAPER's k, not this lab's.
 *
 * break2.test.ts explains the reason and it is measured: the lab raises k so
 * that decryption is guaranteed, the lift threshold is the absolute 0.5 while
 * ||L|| grows like k, so the signature requirement scales as k^2. Break 2
 * attacks a signature scheme and needs no decryption guarantee, so the paper's
 * k = round(sqrt(n)*l) is both honest and 16x cheaper here.
 */
function sectionBreak2(m) {
  const { gghKeygen, paperK } = m.keygen;
  const { inverse, makeRng } = m.matrix;
  const { makeRoundOffSigner, roundOffBoundInf } = m.sign;
  const { kleinBoundInf, kleinSigma, makeKleinSigner, newSampleZStats } = m.klein;
  const { publicKey } = m.verify;
  const { runBreak2 } = m.break2;

  const n = 8;
  const { startN, capN, forgeries, attackSeed } = SEEDS.break2;

  const runOne = (keySeed, signer) => {
    const key = gghKeygen(n, { rng: makeRng(keySeed), k: paperK(n) });
    const built = signer(key);
    const pub = publicKey(key.B, built.boundInf);
    const t0 = performance.now();
    const res = runBreak2({
      pub,
      sign: built.sign,
      rng: makeRng(attackSeed),
      startN,
      capN,
      forgeries,
      // LAB SCORING ONLY. break2.ts consults this once, after the ladder has
      // already stopped, and the artifact keeps the two outcomes in separate
      // columns for the same reason the module does: forging is what an
      // attacker can observe, and recovering R is a different claim.
      groundTruthR: key.R,
    });
    const ms = performance.now() - t0;
    const last = res.attempts[res.attempts.length - 1];
    const match = res.groundTruthMatch ?? null;
    return {
      keySeed,
      ms,
      // OUTCOME 1: the REAL verifier's verdict on fresh forgeries. Public.
      forgeryOk: res.forgeryOk ?? res.ok,
      // OUTCOME 2: the candidate really is R up to sign and permutation. Secret.
      groundTruthRecovered: res.groundTruthRecovered ?? null,
      reason: res.reason,
      trainingSignatures: res.trainingSignatures ?? res.signaturesConsumed,
      heldOutSignatures: res.heldOutSignatures,
      totalSignaturesObserved: res.totalObserved ?? res.totalSignaturesObserved,
      rungs: res.attempts.length,
      forgeriesAccepted: last.forgeriesAccepted,
      forgeriesAttempted: last.forgeriesAttempted,
      groundTruthRowsMatched: match ? match.matched : 0,
      absDetRatio: match ? r6(match.absDetRatio) : null,
      sumA4HeldOut: r6(res.discriminators.sumA4HeldOut),
      sumA4InSample: r6(res.discriminators.sumA4InSample),
      integralityGap: r6(res.discriminators.integralityGap),
      worstIntegralityGap: r6(res.discriminators.worstIntegralityGap),
      covarianceShape: r6(res.discriminators.covarianceShape),
      extra: built.extra ?? null,
    };
  };

  const roundOffRuns = SEEDS.break2.roundOffKeySeeds.map((s) =>
    runOne(s, (key) => ({
      sign: makeRoundOffSigner(key.R, inverse(key.R)),
      boundInf: roundOffBoundInf(key.R),
    })),
  );

  // The Gaussian defence, with the sampler's own counters attached: the fallback
  // count is the one number that would quietly turn Klein into round-off if the
  // rejection loop ever gave up, so it is recorded rather than assumed zero.
  const kleinRuns = SEEDS.break2.kleinKeySeeds.map((s) =>
    runOne(s, (key) => {
      const stats = newSampleZStats();
      const sigma = kleinSigma(key.R);
      const rng = makeRng(s ^ 0x5eed);
      return {
        sign: makeKleinSigner(key.R, rng, sigma, stats),
        boundInf: kleinBoundInf(sigma),
        extra: { sigma: r6(sigma), stats },
      };
    }),
  );

  const summarise = (runs) => ({
    keys: runs.length,
    forgeryOk: runs.filter((r) => r.forgeryOk).length,
    forgerySuccessRate: r6(runs.filter((r) => r.forgeryOk).length / runs.length),
    groundTruthRecovered: runs.filter((r) => r.groundTruthRecovered === true).length,
    msP50: r3(pct(runs.map((r) => r.ms), 0.5)),
    msP95: r3(pct(runs.map((r) => r.ms), 0.95)),
    sumA4HeldOutMin: r6(min(runs.map((r) => r.sumA4HeldOut))),
    sumA4HeldOutMax: r6(max(runs.map((r) => r.sumA4HeldOut))),
    integralityGapMin: r6(min(runs.map((r) => r.integralityGap))),
    integralityGapMax: r6(max(runs.map((r) => r.integralityGap))),
    runs: runs.map(({ extra, ...rest }) => ({ ...rest, ...(extra ? { klein: extra } : {}) })),
  });

  const roundOff = summarise(roundOffRuns);
  const klein = summarise(kleinRuns);

  return {
    claim:
      "C5: the round-off signer leaks its private basis and the REAL verifier accepts the " +
      "forgeries. C5': the same attack learns nothing from a Klein/GPV signer.",
    dimension: n,
    kRule: 'paperK(n) = round(sqrt(n)*l) -- see the note in this section of scripts/evidence.mjs',
    ladder: { startN, capN, forgeries },
    ok: roundOff.forgeryOk === roundOff.keys && klein.forgeryOk === 0,
    roundOff,
    klein,
  };
}

// ---------------------------------------------------------------------------
// Gaussian sampler -- held-out statistics and the fallback counter
// ---------------------------------------------------------------------------

function sectionGaussian(break2Section) {
  const runs = break2Section.klein.runs;
  const draws = runs.reduce((a, r) => a + (r.klein?.stats.draws ?? 0), 0);
  const accepts = runs.reduce((a, r) => a + (r.klein?.stats.accepts ?? 0), 0);
  const fallbacks = runs.reduce((a, r) => a + (r.klein?.stats.fallbacks ?? 0), 0);
  return {
    claim:
      'The Klein sampler is a rejection sampler with a try cap; the fallback to ' +
      'round(c) is a visible degradation, and it must never fire in practice.',
    keys: runs.length,
    candidateDraws: draws,
    accepts,
    acceptanceRate: draws ? r6(accepts / draws) : null,
    // Non-zero here means some coordinate exhausted SAMPLE_Z_TRIES and silently
    // became a round-off sample -- which is the one way this defence could
    // degrade into the scheme it defends against.
    samplerFallbacks: fallbacks,
    heldOut: {
      sumA4Min: break2Section.klein.sumA4HeldOutMin,
      sumA4Max: break2Section.klein.sumA4HeldOutMax,
      integralityGapMin: break2Section.klein.integralityGapMin,
      integralityGapMax: break2Section.klein.integralityGapMax,
      // The in-sample number overfits upward; keeping both is what makes the
      // hold-out split legible rather than a claim.
      sumA4InSample: break2Section.klein.runs.map((r) => r.sumA4InSample),
    },
    roundOffHeldOutForContrast: {
      sumA4Min: break2Section.roundOff.sumA4HeldOutMin,
      sumA4Max: break2Section.roundOff.sumA4HeldOutMax,
    },
    ok: fallbacks === 0,
  };
}

// ---------------------------------------------------------------------------
// HNF -- time, proof time, bit sizes, peak intermediate magnitude
// ---------------------------------------------------------------------------

function sectionHnf(m) {
  const { gghKeygen } = m.keygen;
  const { makeRng } = m.matrix;
  const {
    bigMaxAbs,
    bitsOfInt,
    compareKeySize,
    hnf,
    proveSameLatticeHnf,
    toBigMat,
  } = m.hnf;

  const byDimension = DIMS.map((n) => {
    const key = gghKeygen(n, { rng: makeRng(SEEDS.hnf.keySeedBase + n) });
    const res = hnf(key.B);
    const R = toBigMat(key.R);
    const proof = proveSameLatticeHnf(R, res.H);
    const size = compareKeySize(key.B, res.H);
    // The peak intermediate magnitude, in two places that matter for different
    // reasons: the HNF itself never exceeds d = |det| by construction (every
    // entry is kept reduced mod d), while the PROOF's transform T = H*R^-1 is
    // genuinely huge -- expressing the HNF's rows in the short private basis
    // needs coefficients around 10^111 at n=60, measured.
    const peakT = proof.T ? bigMaxAbs(proof.T) : 0n;
    return {
      n,
      ms: r3(res.ms),
      proofMs: r3(proof.ms),
      proofOk: proof.ok,
      detBits: bitsOfInt(res.d),
      // Decimal digits, not log10: |det| is 10^89.7 at n=60 and must never be
      // formed as a double, so the digit count is read off the BigInt itself.
      detDecimalDigits: res.d.toString().length,
      nontrivialPivots: size.nontrivialPivots,
      basisBits: size.basisBits,
      hnfBits: size.hnfBits,
      hnfDenseBits: size.hnfDenseBits,
      sizeRatio: r6(size.ratio),
      basisBitsPerEntry: r6(size.basisBitsPerEntry),
      largestHnfEntryBits: size.largestHnfEntryBits,
      peakHnfEntryBits: bitsOfInt(bigMaxAbs(res.H)),
      peakProofTransformBits: bitsOfInt(peakT),
      peakProofTransformLog10: peakT === 0n ? 0 : peakT.toString().length - 1,
    };
  });
  return {
    claim:
      'HNF(B) is a canonical basis for the same lattice, proved in exact BigInt ' +
      'arithmetic, and it is a smaller public key at these parameters -- by 10-30%, not by a factor of n.',
    ok: byDimension.every((d) => d.proofOk),
    byDimension,
  };
}

// ---------------------------------------------------------------------------
// bundle -- the shipped asset sizes, when a build is present
// ---------------------------------------------------------------------------

function sectionBundle() {
  const dist = path.join(ROOT, 'dist');
  if (!fs.existsSync(dist)) {
    return { present: false, note: 'dist/ absent -- run `npm run build` before `npm run evidence` to record bundle sizes.' };
  }
  const files = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.isFile()) {
        const buf = fs.readFileSync(p);
        files.push({
          file: path.relative(ROOT, p),
          bytes: buf.length,
          // Gzip is what a Pages visitor actually downloads, so the raw byte
          // count on its own overstates the cost by 3-4x.
          gzipBytes: gzipSync(buf, { level: 9 }).length,
          sha256: createHash('sha256').update(buf).digest('hex').slice(0, 16),
        });
      }
    }
  };
  walk(dist);
  files.sort((a, b) => a.file.localeCompare(b.file));
  return {
    present: true,
    totalBytes: files.reduce((a, f) => a + f.bytes, 0),
    totalGzipBytes: files.reduce((a, f) => a + f.gzipBytes, 0),
    files,
    note: 'Sizes are from the dist/ present at generation time; they change with every build.',
  };
}

// ---------------------------------------------------------------------------
// human-readable summary
// ---------------------------------------------------------------------------

function table(rows) {
  if (rows.length === 0) return '';
  const cols = Object.keys(rows[0]);
  const w = cols.map((c) => Math.max(c.length, ...rows.map((r) => String(r[c] ?? '').length)));
  const line = (cells) => '  ' + cells.map((c, i) => String(c ?? '').padStart(w[i])).join('  ');
  return [line(cols), line(w.map((n) => '-'.repeat(n))), ...rows.map((r) => line(cols.map((c) => r[c])))].join('\n');
}

function printSummary(ev) {
  const out = [];
  const p = (s = '') => out.push(s);

  p(`GGH trapdoor lab -- generated evidence`);
  p(`commit ${ev.provenance.commitShort}${ev.provenance.treeClean ? '' : '+dirty'}  node ${ev.provenance.node}  ${ev.provenance.platform}/${ev.provenance.arch}  ${ev.provenance.timestamp}`);
  p();

  p('I1 same-lattice proof, headroom under 2^53');
  p(table(ev.i1.byDimension.map((d) => ({
    n: d.n, keys: d.keys, pass: d.allPass, maxIntermediate: d.maxIntermediate,
    headroom: d.headroom.toExponential(2), spareBits: d.spareBits.toFixed(1),
  }))));
  p();

  p('I2 decryption bound (sigma = ' + ev.i2.sigma + ')');
  p(table(ev.i2.byDimension.map((d) => ({
    n: d.n, iffMismatches: d.iffMismatches,
    'R actual (med)': d.privateBasis.actualMedian, 'R worst': d.privateBasis.worstCase,
    guaranteed: d.privateBasis.guaranteed, margin: (0.5 / d.privateBasis.worstCase).toFixed(2) + 'x',
    'B actual (med)': d.publicBasis.actualMedian, 'B worst': d.publicBasis.worstCase,
  }))));
  p();

  p('keygen: fraction of random R with det coprime to 6');
  p(table(ev.keygen.byDimension.map((d) => ({
    n: d.n, keys: d.keys, draws: d.candidateDraws,
    acceptance: (d.acceptanceRate * 100).toFixed(1) + '%', meanDraws: d.meanDrawsToAccept.toFixed(2),
  }))));
  p();

  p(`baseline: decryption with raw B, with LLL(B), and with the secret R (LLL row from ${ev.baseline.source})`);
  p(table(ev.baseline.byDimension.map((d) => ({
    n: d.n,
    'raw B': `${d.rawB.decrypted}/${d.rawB.trials}`,
    'LLL(B)': `${d.lllB.decrypted}/${d.lllB.trials}`,
    'secret R': `${d.secretR.decrypted}/${d.secretR.trials}`,
    'worst I2 raw': d.rawB.worstCaseBound, 'worst I2 lll': d.lllB.worstCaseBound,
    'worst I2 R': d.secretR.worstCaseBound,
    'lll ms': d.lllB.lllMs, 'LLL(B) = R up to sign/perm': d.lllB.matchesSecretUpToSignPerm,
  }))));
  p();

  p('Break 1: honest recovery, and the non-congruent negative control');
  p(table(ev.break1.byDimension.map((d) => ({
    n: d.n, verified: `${d.honest.verified}/${d.honest.trials}`,
    p50ms: d.honest.msP50, p95ms: d.honest.msP95,
    'ratio honest': `${d.honest.normRatioMin}-${d.honest.normRatioMax}`,
    'ratio tampered': `${d.tampered.normRatioMin}-${d.tampered.normRatioMax}`,
    'tampered verified': `${d.tampered.verified}/${d.tampered.trials}`,
    separation: d.separation + 'x',
  }))));
  p();

  p(`Break 2 at n=${ev.break2.dimension} (ladder ${ev.break2.ladder.startN}..${ev.break2.ladder.capN}, ${ev.break2.ladder.forgeries} forgeries)`);
  p(table([...ev.break2.roundOff.runs.map((r) => ({ signer: 'round-off', ...r })), ...ev.break2.klein.runs.map((r) => ({ signer: 'Klein', ...r }))].map((r) => ({
    signer: r.signer, keySeed: r.keySeed, forged: `${r.forgeriesAccepted}/${r.forgeriesAttempted}`,
    forgeryOk: r.forgeryOk, 'R recovered': String(r.groundTruthRecovered),
    train: r.trainingSignatures, held: r.heldOutSignatures,
    total: r.totalSignaturesObserved, 'rows matched': r.groundTruthRowsMatched,
    'sumA4 held': r.sumA4HeldOut, 'sumA4 in': r.sumA4InSample, gap: r.integralityGap, ms: r3(r.ms),
  }))));
  p();

  p('Gaussian sampler');
  p(`  draws ${ev.gaussian.candidateDraws}, accepts ${ev.gaussian.accepts} (${(ev.gaussian.acceptanceRate * 100).toFixed(1)}%), fallbacks ${ev.gaussian.samplerFallbacks}`);
  p();

  p('HNF');
  p(table(ev.hnf.byDimension.map((d) => ({
    n: d.n, ms: d.ms, proofMs: d.proofMs, proofOk: d.proofOk, detBits: d.detBits,
    'bits(B)': d.basisBits, 'bits(HNF)': d.hnfBits, ratio: d.sizeRatio,
    'peak |T| 10^': d.peakProofTransformLog10,
  }))));
  p();

  if (ev.bundle.present) {
    p('bundle');
    p(table(ev.bundle.files.map((f) => ({ file: f.file, bytes: f.bytes, gzip: f.gzipBytes, sha256: f.sha256 }))));
  } else {
    p('bundle: ' + ev.bundle.note);
  }
  p();

  const marks = Object.entries(ev.summary.sections).map(([k, v]) => `${v ? 'PASS' : 'FAIL'} ${k}`);
  p('verdicts: ' + marks.join('   '));
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const warnings = [];
  const warn = (msg) => {
    warnings.push(msg);
    process.stderr.write(`WARNING: ${msg}\n`);
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ggh-evidence-'));
  let ev;
  try {
    const m = await loadModules(tmpDir);

    const t0 = performance.now();
    const i1 = sectionI1(m);
    const i2 = sectionI2(m);
    const keygen = sectionKeygen(m);
    const baseline = sectionBaseline(m, warn);
    const break1 = sectionBreak1(m);
    const break2 = sectionBreak2(m);
    const gaussian = sectionGaussian(break2);
    const hnfSec = sectionHnf(m);
    const bundle = sectionBundle();
    const generationMs = performance.now() - t0;

    const sections = {
      i1: i1.ok,
      i2: i2.ok,
      baseline: baseline.ok,
      break1: break1.ok,
      break2: break2.ok,
      gaussian: gaussian.ok,
      hnf: hnfSec.ok,
    };

    ev = {
      schema: 'crypto-lab-ggh-trapdoor/evidence@1',
      provenance: { ...provenance(resolveTimestamp(args.timestamp)), generationMs: r3(generationMs), warnings },
      summary: {
        // A generated artifact that records a broken invariant without saying so
        // would be worse than no artifact at all, so the verdicts are part of it
        // and the process exit code follows them.
        allInvariantsHeld: Object.values(sections).every(Boolean),
        sections,
      },
      i1,
      i2,
      keygen,
      baseline,
      break1,
      break2,
      gaussian,
      hnf: hnfSec,
      bundle,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, JSON.stringify(ev, null, 2) + '\n');

  if (!args.quiet) {
    process.stdout.write(printSummary(ev) + '\n');
    process.stdout.write(`\nwrote ${path.relative(ROOT, args.out)} (${(fs.statSync(args.out).size / 1024).toFixed(1)} kB) in ${(ev.provenance.generationMs / 1000).toFixed(1)} s\n`);
  }

  if (!ev.summary.allInvariantsHeld) {
    const failed = Object.entries(ev.summary.sections).filter(([, v]) => !v).map(([k]) => k);
    process.stderr.write(`\nFAILED invariants: ${failed.join(', ')} -- the artifact records the failure; it is not a generator bug.\n`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(String(err?.stack ?? err) + '\n');
  process.exit(1);
});
