import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

// The demo build has no backend and makes no network calls, so it can ship a
// locked-down CSP. Dev mode can't: Vite's HMR injects inline scripts.
const DEMO_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ')

function demoCsp(): Plugin {
  return {
    name: 'demo-csp',
    transformIndexHtml: () => [
      {
        tag: 'meta',
        attrs: { 'http-equiv': 'Content-Security-Policy', content: DEMO_CSP },
        injectTo: 'head-prepend',
      },
    ],
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => ({
  // `--mode demo` builds the public GitHub Pages site, served from /Lightweight-SIEM/.
  base: mode === 'demo' ? '/Lightweight-SIEM/' : '/',
  plugins: mode === 'demo' ? [react(), demoCsp()] : [react()],
}))
