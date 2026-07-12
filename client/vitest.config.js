import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.js"],
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary", "lcov", "html", "json-summary"],
      reportsDirectory: "./coverage",
      include: ["lib.js"],
      exclude: ["script.js"],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },
  },
});
