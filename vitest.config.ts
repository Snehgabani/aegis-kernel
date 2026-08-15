import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 15000,
    hookTimeout: 15000,
  },
  resolve: {
    alias: {
      '@aegis-kernel/core': path.resolve(__dirname, 'packages/core/src/index.ts'),
      '@aegis-kernel/evals': path.resolve(__dirname, 'packages/evals/src/index.ts'),
      '@aegis-kernel/mcp': path.resolve(__dirname, 'packages/mcp/src/index.ts'),
      '@aegis-kernel/openai': path.resolve(__dirname, 'packages/openai/src/index.ts'),
      '@aegis-kernel/anthropic': path.resolve(__dirname, 'packages/anthropic/src/index.ts'),
      '@aegis-kernel/langchain': path.resolve(__dirname, 'packages/langchain/src/index.ts'),
    },
  },
});
