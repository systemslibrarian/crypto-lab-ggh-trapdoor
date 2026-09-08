import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the PRODUCTION build served by `vite preview`, so what passes
 * here is what ships. Two projects, separated by filename:
 *
 *   - `a11y`   — `e2e/a11y.spec.ts`, the axe + arithmetic WCAG gate. Chromium
 *     only, because a contrast oracle that measures composited pixels has to be
 *     deterministic to be a gate at all; three engines' rounding would turn it
 *     into three different numbers for the same paint.
 *   - `claims` — `e2e/claims.spec.ts`, the suite that checks the page tells the
 *     truth about the lattice: I1 (U·V = I over the integers), I2 (the
 *     round-off bound), and both breaks checked against the real decryptor and
 *     the real verifier rather than against the secret.
 *
 * `npm run test:a11y` and `npm run test:claims` scope to one project each;
 * `npm run test:e2e` runs both. CI must run BOTH plus `npm test` — a deploy job
 * that runs only the a11y half never gates the cryptography, which a fleet
 * sweep found in 29 repos.
 */

/**
 * The preview port.
 *
 * It must be unique across every sibling lab IN COMMITTED STATE: with 170+ labs
 * checked out side by side, `reuseExistingServer` below silently adopts a
 * preview already listening on this port, and a gate that scans a DIFFERENT
 * lab's build is worse than no gate — that has really happened in this fleet,
 * where one lab spent a session reporting a neighbour's violations. Never the
 * Vite default 4173 for the same reason: it is the one port every unconfigured
 * lab lands on.
 *
 * Kept as a named constant so the two URLs and the preview command cannot drift
 * apart, and so re-assigning the port is a one-line change.
 */
// 4666, verified free across all 167 committed sibling playwright configs AND
// their working trees on 2026-09-08. Note the check has to match BOTH spellings
// in use in this fleet -- `localhost:NNNN` and a `const PORT = NNNN` constant.
// Grepping only for the first form is how 4626 initially looked free here when
// crypto-lab-downgrade-wire already holds it in committed state (and
// crypto-lab-factor-forge in its working tree).
const PORT = 4666;
const BASE = '/crypto-lab-ggh-trapdoor/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  // Per-test default. The a11y spec overrides to 30 minutes: it drives both
  // breaks — an LLL embedding attack and a fourth-moment descent over live
  // signatures — and scans ~18 states with two axe passes and two composited
  // contrast walks apiece.
  timeout: 90_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    // Dark is the ONLY theme this lab ships: `data-theme="dark"` is pinned on
    // <html> and there is no toggle. Setting it here means the emulated OS
    // preference agrees with the pin instead of quietly contradicting it.
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // BUILD BEFORE SERVING. `vite preview` serves whatever is already sitting in
    // dist/, so without `npm run build &&` in front, a build that FAILS leaves
    // the previous good bundle in place and the whole suite passes green against
    // source that no longer compiles. That silently invalidates mutation
    // testing, which is the only evidence any of these tests have teeth. With
    // the build first, a compile error aborts the run instead:
    // "Process from config.webServer was not able to start. Exit code: 2".
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    // The build compiles the lattice modules and the LLL / descent worker before
    // the preview starts, so this budget covers `tsc --noEmit` plus `vite build`,
    // not just server startup.
    timeout: 120_000,
  },
});
