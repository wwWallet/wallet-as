import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/integration/setup.ts"],
    include: ["test/integration/**/*.test.ts"],
  },
});