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
  };
});