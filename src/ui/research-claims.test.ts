import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (relative: string): string =>
  readFileSync(new URL(`../../${relative}`, import.meta.url), 'utf8');

describe('primary-source claim boundaries', () => {
  it('does not assign an unsupported 2010 endpoint to the 1999 GGH challenge paper', () => {
    const copy = [
      read('README.md'),
      read('src/ui/act5.ts'),
      read('src/ui/baseline-panel.ts'),
    ].join('\n');

    expect(copy).not.toContain('held out until 2010');
    expect(copy).toContain('dimension 400 remained unsolved');
    expect(copy).toContain('plaintext modulo 6');
    expect(copy).toContain('partial plaintext information');
  });

  it('qualifies uniform signature samples by the message-distribution assumption', () => {
    const copy = [read('README.md'), read('index.html'), read('src/ui/act5.ts')].join('\n');

    expect(copy).not.toContain('Every deterministic Babai signature is a uniform sample');
    expect(copy).not.toContain('drawn uniformly from the parallelepiped');
    expect(copy).toContain('idealized message-distribution assumption');
    expect(copy).toContain('approximately uniform');
    expect(copy).toContain('sufficiently wide');
  });
});
