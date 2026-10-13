import { useCallback, useEffect, useState } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'breakglass-theme';
const LIGHT_QUERY = '(prefers-color-scheme: light)';

function readPreference(): ThemePreference {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value === 'light' || value === 'system' ? value : 'dark';
  } catch {
    return 'dark';
  }
}

function prefersLight(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(LIGHT_QUERY).matches;
}

/** applyThemePreference resolves "system" and sets data-theme; dark is the design default. */
export function applyThemePreference(preference: ThemePreference): void {
  const light = preference === 'light' || (preference === 'system' && prefersLight());
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
}

/** useTheme is dark by default; "system" follows the OS setting live. */
export function useTheme(): [ThemePreference, (preference: ThemePreference) => void] {
  const [preference, setPreference] = useState<ThemePreference>(readPreference);

  useEffect(() => {
    applyThemePreference(preference);
    if (preference !== 'system' || typeof window.matchMedia !== 'function') return;
    const query = window.matchMedia(LIGHT_QUERY);
    const onChange = () => applyThemePreference('system');
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, [preference]);

  const update = useCallback((next: ThemePreference) => {
    setPreference(next);
    try {
      if (next === 'dark') window.localStorage.removeItem(STORAGE_KEY);
      else window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Storage may be unavailable (private mode); the choice then lasts for this page only.
    }
  }, []);

  return [preference, update];
}

export function initialThemePreference(): ThemePreference {
  return readPreference();
}
