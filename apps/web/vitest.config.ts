import path from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Audit-tail tests use real filesystem temp dirs; node env (not jsdom).
    environment: "node",
    // Tail tests open chokidar watchers; default 5s timeout is plenty,
    // but the 500ms-push assertion uses fake timers in some cases.
    testTimeout: 5_000,
    include: ["__tests__/**/*.test.ts"],
  },
  resolve: {
    // Match the @/* path alias from tsconfig.json so test imports
    // (`import … from "@/lib/audit-tail"`) resolve the same way they
    // do under Next.js.
    alias: {
      "@": path.resolve(__dirname, "."),
    },
  },
});
