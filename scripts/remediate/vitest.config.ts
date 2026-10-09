import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/upload-sarif.ts'],
      thresholds: {
        statements: 70,
        branches: 65,
        functions: 75,
        lines: 70,
        'src/engine.ts': { statements: 85, branches: 70, functions: 100, lines: 85 },
      },
    },
  },
});
