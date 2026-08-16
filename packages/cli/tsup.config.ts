import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  platform: 'node',
  target: 'node18',
  shims: true,
  noExternal: [/@aegis-kernel\/.*/, 'commander', 'picocolors', 'yaml'],
});
