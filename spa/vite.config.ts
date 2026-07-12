import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');

  return {
    plugins: [react()],
    optimizeDeps: {
      exclude: ['lucide-react'],
    },
    envPrefix: 'VITE_',
    server: {
      port: parseInt(env.VITE_SPA_PORT || '5173'),
      historyApiFallback: true,
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      css: false,
      coverage: {
        provider: 'v8',
        reporter: ['text', 'text-summary', 'html', 'json-summary', 'lcov'],
        reportsDirectory: './coverage',
        exclude: [
          'node_modules/',
          'src/test/setup.ts',
          'src/main.tsx',
          'src/vite-env.d.ts',
          '**/*.config.{js,ts}',
          'dist/',
        ],
        thresholds: {
          lines: 80,
          functions: 80,
          branches: 80,
          statements: 80,
        },
      },
    },
  };
});
