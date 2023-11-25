import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // server: {
  //   proxy: {
  //     '/api/*': {
  //       target: 'http://backend.default.svc.cluster.local:8000',
  //       changeOrigin: true,
  //       secure: false,
  //       ws: true,
  //       rewrite: (path) => path.replace(/^\/api/, '')
  //     }
  //   }
  // }
})
