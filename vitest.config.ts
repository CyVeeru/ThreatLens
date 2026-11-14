import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    globals: false,
    pool: "forks",
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["client/src/**/*.{ts,tsx}", "server/**/*.ts", "shared/**/*.ts"],
      exclude: ["**/*.d.ts", "dist/**", "node_modules/**"],
    },
  },
  resolve: {
    alias: {
      // fileURLToPath keeps Windows drive letters intact (URL.pathname yields "/C:/...").
      "@": fileURLToPath(new URL("./client/src", import.meta.url)),
      "@shared": fileURLToPath(new URL("./shared", import.meta.url)),
    },
  },
});
