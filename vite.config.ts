import { defineConfig, configDefaults } from 'vitest/config';

// base MUST match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-ggh-trapdoor/
// Every asset reference in this repo is relative or Vite-resolved; a root-absolute
// path such as /assets/x.js resolves to systemslibrarian.github.io/assets/x.js and 404s.
export default defineConfig({
  base: '/crypto-lab-ggh-trapdoor/',
  worker: {
    // The LLL / descent worker is an ES module and is instantiated with
    // new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' }),
    // which is the only form Vite rewrites to a base-prefixed emitted chunk.
    format: 'es',
  },
  test: {
    // Colocated unit tests only; keep Playwright specs in e2e/ out of the Vitest run.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
});
