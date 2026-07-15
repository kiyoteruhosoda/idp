import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  build: {
    outDir: '../assets/react',
    emptyOutDir: true,
    sourcemap: true,
    lib: {
      entry: 'src/main.tsx',
      formats: ['es'],
      fileName: () => 'app.js',
    },
    rollupOptions: {
      output: {
        assetFileNames: 'app.[name][extname]',
      },
    },
  },
});
