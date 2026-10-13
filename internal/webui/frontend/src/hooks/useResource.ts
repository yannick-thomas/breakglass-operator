import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { SessionExpiredError } from '../api/client';

export interface Resource<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  /** Time of the last successful load, for the live indicator. */
  updatedAt: number | undefined;
  reload: () => Promise<void>;
}

/**
 * useResource loads data once and then every pollMs while the page is
 * visible. Only the newest response is applied, so a slow earlier poll can
 * never overwrite fresher data.
 */
export function useResource<T>(load: () => Promise<T>, pollMs?: number): Resource<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number>();
  const sequence = useRef(0);
  const loadRef = useRef(load);
  useLayoutEffect(() => {
    loadRef.current = load;
  });

  const reload = useCallback(async () => {
    const id = ++sequence.current;
    try {
      const result = await loadRef.current();
      if (id === sequence.current) {
        setData(result);
        setError(undefined);
        setUpdatedAt(Date.now());
      }
    } catch (err) {
      if (err instanceof SessionExpiredError) return;
      if (id === sequence.current) setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      if (id === sequence.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    if (!pollMs) return;

    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') void reload();
    }, pollMs);
    const onVisible = () => {
      if (document.visibilityState === 'visible') void reload();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [reload, pollMs]);

  return { data, error, loading, updatedAt, reload };
}
