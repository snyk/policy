import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    dir: 'test',
    coverage: {
      provider: 'c8',
      reporter: ['text', 'html'],

      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
});
