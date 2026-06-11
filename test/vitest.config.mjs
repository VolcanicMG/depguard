import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globalSetup: './globalSetup.mjs',
    // E2E budget: each test spawns the binary + npm + sometimes docker.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Tests bind localhost ports and spawn npm; keep files sequential so
    // port/temp churn stays predictable. Tests within a file already run
    // sequentially by default.
    fileParallelism: false,
  },
});
