import path from 'path';

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import mkcert from 'vite-plugin-mkcert';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    mkcert(),
  ],
  server: {
    // https: true,
    port: 3000,
    host: 'dev.vercre.io',
  },
  resolve: {
    // eslint-disable-next-line no-undef
    alias: { '@': path.resolve(__dirname, './src') },
  }
});
