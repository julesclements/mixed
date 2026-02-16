import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');

  return {
    plugins: [react()],
    optimizeDeps: {
      exclude: ['lucide-react'],
    },
    define: {
      'process.env.VITE_CLIENT_ID': JSON.stringify(env.VITE_CLIENT_ID),
      'process.env.VITE_PING_BASE_URL': JSON.stringify(env.VITE_PING_BASE_URL),
    },
    envPrefix: 'VITE_',
    server: {
      historyApiFallback: true,
    },
  };
});