import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/sora';
import '@fontsource-variable/geist-mono';
import '../shared/theme.css';
import './panel.css';
import { startWs } from '../shared/ws';
import { App } from './App';

startWs();
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
