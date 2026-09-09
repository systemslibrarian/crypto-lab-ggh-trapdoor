#!/usr/bin/env node
/**
 * `npm run mutate` -- prove the tests bite, on the trust boundaries that matter.
 *
 * WHY THIS EXISTS. CRYPTO-LAB-TEMPLATE.md section 4.1c requires mutation
 * discipline: break a condition in the SOURCE, confirm the build still succeeds,
 * confirm the bundle hash changed, confirm the owning test FAILS, restore. The
 * repo documented that discipline and had no way to repeat it, so "the tests
 * bite" was a claim about a session that nobody could re-run. This is that
 * session, as a command.
 *
 * The five steps per mutation, in the template's order and for its reasons:
 *
 *   1. apply an exact, unique string replacement in a source file (never a test);
 *   2. `npm run build` must SUCCEED -- a mutation that breaks `tsc` proves
 *      nothing, because the suite would be failing on a compile error rather
 *      than on the maths;
 *   3. the built bundle hash must CHANGE -- proof the mutation reached the
 *      artifact and was not, say, dead code;
 *   4. the named owning test must FAIL;
 *   5. restore, and the bundle hash must return to its baseline value.
 *
 * A mutation that leaves the suite green is reported as SURVIVED and this
 * command exits non-zero. A survivor is evidence about the tests (or about
 * unreachable source), and the fix is a better test -- never a quieter harness.
 * Nothing here may be relaxed to make the table green.
 *
 * SAFETY. Every file is restored in a `finally`, and again from a SIGINT /
 * SIGTERM / uncaughtException handler, because a run that dies mid-mutation
 * would otherwise strand an inverted condition in a repo other agents are
 * editing. The final restore is verified byte for byte against the bytes read
 * before the first mutation.
 *
 * It follows that a source file is briefly WRONG on disk while this runs, and
 * that `npm run build` rewrites dist/. Do not run it against a tree someone
 * else is editing: an edit landing inside that window is overwritten by the
 * restore, and the run says so when it detects one.
 *
 * Every mutation runs even when an earlier one survives -- one bad verdict must
 * not hide the other five -- and the exit code reports the whole table.
 *
 * Usage:
 *   node scripts/mutate.mjs [--list] [--only <id>[,<id>...]]
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The curated mutation set.
 *
 * One mutation per trust boundary the lab's honesty rests on, chosen from audit
 * finding 13. Each `find` must occur EXACTLY ONCE in its file: a replacement
 * that silently matched twice, or not at all, would produce a false verdict, and
 * the template's own war story is a mutation that no-op'd and read as "the
 * oracle is dead".
 */
const MUTATIONS = [
  {
    id: 'i1-unimodular',
    claim: 'I1: U*V must be exactly the identity, which is what supplies det(U) = +-1.',
    file: 'src/lattice/invariants.ts',
    find: 'const uTimesVIsIdentity = entriesSafe && isIdentity(matmul(U, V, stats));',
    replace: 'const uTimesVIsIdentity = entriesSafe && !isIdentity(matmul(U, V, stats));',
    test: 'src/lattice/lattice.test.ts',
    why: 'Inverts the unimodularity decision: the same-lattice proof now passes only when U*V is NOT I.',
  },
  {
    id: 'i2-threshold',
    claim: 'I2: Babai round-off succeeds iff max|e*basis^-1| < 1/2, and 1/2 is the exact constant.',
    file: 'src/lattice/roundoff.ts',
    find: 'predictsSuccess: actual < 0.5,',
    replace: 'predictsSuccess: actual < 0.06,',
    test: 'src/lattice/lattice.test.ts',
    // 0.06 is not arbitrary. MEASURED by scripts/evidence.mjs, the private-basis
    // `actual` medians are 0.1008 (n=8), 0.0843 (16), 0.0730 (32) and 0.0616
    // (60), so 0.06 sits inside that population and flips real ciphertexts from
    // "predicted to decrypt" to "predicted to fail" while they still decrypt --
    // which is exactly what an iff test must catch. A threshold anywhere in
    // (0.14, 1.3) would SURVIVE, and that is a fact about the source, not a weak
    // test: the private and public populations are an order of magnitude apart,
    // and that gap IS the trapdoor. Only a mutation landing inside a measured
    // population can be caught by measurement.
    why: 'Moves the 1/2 threshold into the measured private-basis population, breaking the exact iff.',
  },
  {
    id: 'break1-reencryption',
    claim: 'I5: Break 1 may only claim success through the re-encryption check, never otherwise.',
    file: 'src/attack/break1.ts',
    find: 'if (chk.ok) {',
    replace: 'if (chk.ok || tried >= 1) {',
    test: 'src/attack/break1.test.ts',
    why: 'Accepts the first candidate message whatever the re-encryption check said, so a rejected attack reports success.',
  },
  {
    id: 'break2-forgery-tolerance',
    claim: 'C5: every one of the forgeries must verify; the real verifier decides, not the attack.',
    file: 'src/attack/break2.ts',
    find: 'const forgeryOk = Rhat !== null && accepted === forgeries && forgeries > 0;',
    replace: 'const forgeryOk = Rhat !== null && accepted >= forgeries - 1 && forgeries > 0;',
    test: 'src/attack/break2.test.ts',
    why: 'Tolerates one rejected forgery, turning "the verifier accepted all of them" into "nearly all".',
  },
  {
    id: 'verifier-finite-guard',
    claim: 'The verifier must fail closed: a non-finite signature entry is rejected, never compared.',
    file: 'src/sign/verify.ts',
    // `false &&` rather than deleting the line, so the guard is REMOVED (it can
    // no longer reject anything) while `s` and the reason string stay
    // referenced -- a deletion would leave an unused binding and `tsc` would
    // fail under noUnusedLocals, and a mutation that breaks the build proves
    // nothing.
    //
    // NaN is the whole point: every comparison against NaN is false, so with
    // this guard gone a NaN signature slips past `Math.abs(s[i]) > TWO53`,
    // past `Number.isInteger`, and into the exact BigInt path.
    //
    // TOLERATED IF ABSENT. When this harness was written, verify.ts was being
    // rewritten in parallel to add exactly these fail-closed guards (audit
    // finding 2). If the string below is not in the file, this entry reports
    // SKIPPED rather than inventing a target: a `find` that silently matches
    // nothing is the false-KILLED failure section 4.1c warns about.
    find: "if (!Number.isFinite(s[i])) return bad('bad-vector(nonfinite)'",
    replace: "if (false && !Number.isFinite(s[i])) return bad('bad-vector(nonfinite)'",
    tolerateMissing: true,
    detect: /Number\.isFinite|bad-vector\(nonfinite\)|bad-vector\(length\)/,
    test: 'src/sign/verify.test.ts',
    why: 'Removes the fail-closed finiteness guard, so a NaN signature entry reaches the arithmetic.',
  },
  {
    id: 'break2-holdout-merge',
    claim: 'C5\': the fourth moment must be scored on signatures the descent never saw.',
    file: 'src/attack/break2.ts',
    find: 'const heldW = applyWhitening(held, wh.Linv);',
    replace: 'const heldW = applyWhitening(train, wh.Linv);',
    test: 'src/attack/break2.test.ts',
    why: 'Scores the "held-out" moment on the training set, so the overfit reads as structure.',
  },
];

// ---------------------------------------------------------------------------
// process helpers
// ---------------------------------------------------------------------------

/**
 * Strip ANSI. Vitest colours its FAIL lines even with NO_COLOR set, and the
 * escape codes end up inside the table cell and wreck the column widths.
 */
const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

function run(cmd, args) {
  const t0 = Date.now();
  const res = spawnSync(cmd, args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, CI: '1', FORCE_COLOR: '0', NO_COLOR: '1' },
  });
  return {
    ok: res.status === 0,
    status: res.status,
    ms: Date.now() - t0,
    out: stripAnsi(`${res.stdout ?? ''}${res.stderr ?? ''}`),
  };
}

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';

const build = () => run(npm, ['run', 'build']);
/**
 * The owning test, from the fast unit suite.
 *
 * Vitest only, deliberately: the Playwright projects take minutes and drive a
 * page other agents may be editing, so a mutation run that needed them would
 * never be executed and this file would rot the way the prose it replaces did.
 */
const owningTest = (file) => run(npx, ['vitest', 'run', file, '--reporter=dot']);

/**
 * Hash of the built artifact.
 *
 * Over the CONTENT of every emitted file, sorted, and not over the file names:
 * Vite puts a content hash in the name, so hashing names would double-count the
 * same change and would also make the baseline comparison a tautology.
 */
function bundleHash() {
  const dist = path.join(ROOT, 'dist');
  if (!fs.existsSync(dist)) return null;
  const hashes = [];
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.isFile()) hashes.push(createHash('sha256').update(fs.readFileSync(p)).digest('hex'));
    }
  };
  walk(dist);
  hashes.sort();
  return createHash('sha256').update(hashes.join('\n')).digest('hex').slice(0, 16);
}

// ---------------------------------------------------------------------------
// the mutated-file registry, so a crash cannot strand a mutation
// ---------------------------------------------------------------------------

/** absolute path -> the exact bytes read before anything was written. */
const pristine = new Map();

function readPristine(rel) {
  const abs = path.join(ROOT, rel);
  if (!pristine.has(abs)) pristine.set(abs, fs.readFileSync(abs));
  return pristine.get(abs);
}

function restoreAll() {
  for (const [abs, bytes] of pristine) {
    try {
      if (!fs.readFileSync(abs).equals(bytes)) fs.writeFileSync(abs, bytes);
    } catch (err) {
      process.stderr.write(`CRITICAL: could not restore ${abs}: ${err}\n`);
    }
  }
}

let restoreHooked = false;
function hookRestore() {
  if (restoreHooked) return;
  restoreHooked = true;
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => {
      restoreAll();
      process.exit(130);
    });
  }
  process.on('uncaughtException', (err) => {
    restoreAll();
    process.stderr.write(String(err?.stack ?? err) + '\n');
    process.exit(1);
  });
}

// ---------------------------------------------------------------------------
// one mutation
// ---------------------------------------------------------------------------

function applyMutation(mut, baselineHash, log) {
  const abs = path.join(ROOT, mut.file);
  const result = {
    id: mut.id,
    file: mut.file,
    test: mut.test,
    verdict: 'PENDING',
    buildOk: null,
    hashChanged: null,
    testFailed: null,
    restored: null,
    ms: 0,
    detail: '',
  };
  const t0 = Date.now();

  if (!fs.existsSync(abs)) {
    result.verdict = 'SKIPPED';
    result.detail = `${mut.file} does not exist`;
    result.ms = Date.now() - t0;
    return result;
  }

  const original = readPristine(mut.file);
  const text = original.toString('utf8');

  // Exactly one occurrence, or the verdict would be meaningless: zero means the
  // mutation silently no-ops and reads as a dead oracle, two means the harness
  // is changing something it did not name.
  const occurrences = mut.find ? text.split(mut.find).length - 1 : 0;
  if (occurrences !== 1) {
    // `tolerateMissing` entries target code another agent is still writing.
    // Absent is SKIPPED (and says what to do); ambiguous is still INVALID.
    result.verdict = occurrences === 0 && mut.tolerateMissing ? 'SKIPPED' : 'INVALID';
    result.detail =
      occurrences === 0 && mut.tolerateMissing
        ? `the target guard is not in ${mut.file}${mut.detect && mut.detect.test(text) ? ` (though something matching ${mut.detect} is -- pin its exact text as \`find\` in scripts/mutate.mjs)` : ''}`
        : `target string occurs ${occurrences} times in ${mut.file} (needs exactly 1) -- the source moved under this harness`;
    result.ms = Date.now() - t0;
    return result;
  }

  const mutated = text.replace(mut.find, mut.replace);
  try {
    fs.writeFileSync(abs, mutated);

    // Verify the mutation actually APPLIED before trusting anything downstream.
    const onDisk = fs.readFileSync(abs, 'utf8');
    if (!onDisk.includes(mut.replace) || onDisk.includes(mut.find)) {
      result.verdict = 'INVALID';
      result.detail = 'the replacement did not apply on disk';
      return result;
    }

    log(`  building with ${mut.id} applied...`);
    const b = build();
    result.buildOk = b.ok;
    if (!b.ok) {
      result.verdict = 'INVALID';
      result.detail = `npm run build FAILED under the mutation, so the suite would fail on a compile error and prove nothing:\n${tail(b.out, 12)}`;
      return result;
    }

    const mutatedHash = bundleHash();
    result.hashChanged = mutatedHash !== null && mutatedHash !== baselineHash;
    if (!result.hashChanged) {
      result.verdict = 'INVALID';
      result.detail = `bundle hash did not change (${mutatedHash}); the mutation never reached the artifact`;
      return result;
    }

    log(`  running ${mut.test} (must FAIL)...`);
    const t = owningTest(mut.test);
    result.testFailed = !t.ok;
    result.verdict = t.ok ? 'SURVIVED' : 'KILLED';
    result.detail = t.ok
      ? `${mut.test} stayed GREEN under the mutation -- the claim is not covered by that suite`
      : firstFailure(t.out);
  } finally {
    // If the bytes on disk are not the ones this harness wrote, somebody else
    // edited the file while the mutation was live. Restoring is still the right
    // move -- leaving an inverted condition in a shared tree is far worse than
    // losing an edit that is still in someone's editor -- but it must be said
    // out loud, because the restore discards that concurrent write.
    const before = fs.readFileSync(abs);
    if (!before.equals(Buffer.from(mutated))) {
      result.detail += `${result.detail ? '\n' : ''}NOTE: ${mut.file} changed on disk while the mutation was applied; the restore overwrote that change.`;
    }
    fs.writeFileSync(abs, original);
    result.restored = fs.readFileSync(abs).equals(original);
    result.ms = Date.now() - t0;
  }
  return result;
}

/** Last `n` non-empty lines, for a failure excerpt that fits on screen. */
function tail(text, n) {
  const lines = text.split('\n').filter((l) => l.trim() !== '');
  return lines.slice(-n).map((l) => '    ' + l).join('\n');
}

/** The first assertion vitest reported, so the table says WHY the test bit. */
function firstFailure(out) {
  const m = out.match(/FAIL\s+(\S+)\s*>\s*(.+)/);
  if (m) return `${m[1]} > ${m[2]}`.trim().slice(0, 120);
  const lines = out.split('\n').filter((l) => /AssertionError|expected|FAIL/.test(l));
  return (lines[0] ?? 'test failed').trim().slice(0, 120);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--list')) {
    for (const m of MUTATIONS) process.stdout.write(`${m.id.padEnd(28)} ${m.file} -> ${m.test}\n`);
    return 0;
  }
  const onlyIdx = argv.indexOf('--only');
  const only = onlyIdx >= 0 ? (argv[onlyIdx + 1] ?? '').split(',').filter(Boolean) : null;
  const selected = only ? MUTATIONS.filter((m) => only.includes(m.id)) : MUTATIONS;
  if (selected.length === 0) throw new Error(`no mutation matched --only ${only?.join(',')}`);

  const log = (s) => process.stdout.write(s + '\n');
  const t0 = Date.now();

  hookRestore();
  log('mutation harness -- baseline build first, so the hash comparison means something');
  const baseBuild = build();
  if (!baseBuild.ok) {
    process.stderr.write(`baseline \`npm run build\` FAILED; fix the tree before mutating:\n${tail(baseBuild.out, 20)}\n`);
    return 1;
  }
  const baselineHash = bundleHash();
  log(`  baseline bundle ${baselineHash} (${(baseBuild.ms / 1000).toFixed(1)} s)`);

  const results = [];
  try {
    for (const mut of selected) {
      log(`\n[${mut.id}] ${mut.claim}`);
      log(`  ${mut.file}: ${mut.why}`);
      results.push(applyMutation(mut, baselineHash, log));
      const r = results[results.length - 1];
      log(`  -> ${r.verdict}${r.detail ? ': ' + r.detail.split('\n')[0] : ''} (${(r.ms / 1000).toFixed(1)} s)`);
    }
  } finally {
    restoreAll();
  }

  // Step 5 for the run as a whole: the tree is back, and the artifact with it.
  log('\nrestoring the baseline build...');
  const finalBuild = build();
  const finalHash = bundleHash();
  const hashReturned = finalBuild.ok && finalHash === baselineHash;
  log(`  bundle ${finalHash} ${hashReturned ? '== baseline' : '!= baseline ' + baselineHash}`);

  const rows = results.map((r) => ({
    mutation: r.id,
    file: r.file.replace(/^src\//, ''),
    build: r.buildOk === null ? '-' : r.buildOk ? 'ok' : 'FAILED',
    'hash changed': r.hashChanged === null ? '-' : r.hashChanged ? 'yes' : 'NO',
    'owning test': r.test.replace(/^src\//, ''),
    'test failed': r.testFailed === null ? '-' : r.testFailed ? 'yes' : 'NO',
    verdict: r.verdict,
    s: (r.ms / 1000).toFixed(1),
  }));
  log('\n' + table(rows));

  for (const r of results) {
    if (r.detail && r.verdict !== 'KILLED') log(`\n${r.id}: ${r.detail}`);
  }

  const killed = results.filter((r) => r.verdict === 'KILLED');
  const survived = results.filter((r) => r.verdict === 'SURVIVED');
  const skipped = results.filter((r) => r.verdict === 'SKIPPED');
  const invalid = results.filter((r) => r.verdict === 'INVALID');
  const unrestored = results.filter((r) => r.restored === false);

  log(
    `\n${killed.length} killed, ${survived.length} survived, ${skipped.length} skipped, ` +
      `${invalid.length} invalid, in ${((Date.now() - t0) / 1000).toFixed(1)} s`,
  );

  if (unrestored.length > 0) {
    process.stderr.write(`CRITICAL: not restored: ${unrestored.map((r) => r.file).join(', ')}\n`);
    return 1;
  }
  if (!hashReturned) {
    process.stderr.write(
      'the post-run bundle hash does not match the baseline. Either the build is not ' +
        'deterministic or something else wrote to the tree during the run; do not trust ' +
        'the verdicts above until it does.\n',
    );
    return 1;
  }
  if (survived.length > 0) {
    process.stderr.write(
      `SURVIVED: ${survived.map((r) => r.id).join(', ')} -- the owning test stayed green while the ` +
        'source was wrong. Strengthen the test (or delete the unreachable branch); do not ' +
        'weaken this harness.\n',
    );
    return 1;
  }
  if (invalid.length > 0) {
    process.stderr.write(`INVALID: ${invalid.map((r) => r.id).join(', ')} -- these prove nothing and must be repaired.\n`);
    return 1;
  }
  return 0;
}

function table(rows) {
  if (rows.length === 0) return '(no mutations)';
  const cols = Object.keys(rows[0]);
  const w = cols.map((c) => Math.max(c.length, ...rows.map((r) => String(r[c] ?? '').length)));
  const line = (cells) => '  ' + cells.map((c, i) => String(c ?? '').padEnd(w[i])).join('  ');
  return [line(cols), line(w.map((n) => '-'.repeat(n))), ...rows.map((r) => line(cols.map((c) => r[c])))].join('\n');
}

try {
  process.exitCode = main();
} catch (err) {
  restoreAll();
  process.stderr.write(String(err?.stack ?? err) + '\n');
  process.exitCode = 1;
}
