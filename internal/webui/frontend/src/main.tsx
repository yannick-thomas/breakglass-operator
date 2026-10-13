import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createApi } from './api/client';
import { Toaster } from './components/Toaster';
import { applyThemePreference, initialThemePreference } from './hooks/useTheme';
import './styles/global.css';

applyThemePreference(initialThemePreference());

const root = document.getElementById('root');
if (!root) throw new Error('missing #root element');

createRoot(root).render(
  <StrictMode>
    <Toaster>
      <App api={createApi()} />
    </Toaster>
  </StrictMode>,
);
