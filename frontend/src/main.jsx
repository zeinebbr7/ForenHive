import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import '../assets/style.css';

// React is taking over → cancel the boot watchdog injected by index.html
if (typeof window !== 'undefined' && window.__fhBootWatchdog) {
  clearTimeout(window.__fhBootWatchdog);
  delete window.__fhBootWatchdog;
}

const rootEl = document.getElementById('root');
// Wipe the boot placeholder before React renders so the splash never lingers.
if (rootEl) rootEl.innerHTML = '';

createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
