import { defineConfig } from 'tsup';

// The published package is self-contained: @fofonet/door-core is not
// published, so it is bundled in (from source, via the "development"
// condition) and tree-shaken to what the verifier uses. Its runtime
// dependencies stay external and are this package's own dependencies.
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm'],
  platform: 'neutral',
  target: 'es2022',
  outDir: 'dist',
  clean: true,
  sourcemap: false,
  splitting: false,
  noExternal: ['@fofonet/door-core'],
  dts: true,
  tsconfig: 'tsconfig.build.json',
  esbuildOptions(options) {
    options.conditions = ['development', 'import', 'default'];
  },
});
