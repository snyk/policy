import { resolve } from 'path'
import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'lib/index.ts'),
      fileName: 'index', // extension added automatically based on `format`
      formats: ["es", "cjs"],
    },
    rollupOptions: {
        // externalize node dependencies
        external: ['fs', 'path', 'url', 'util'],
      },
  },
  plugins: [
    dts({
      rollupTypes: true,
    }),
  ],
  test: {
    globals: true,
    dir: 'test',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],

      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },
})
