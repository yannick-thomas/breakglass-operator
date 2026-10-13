import { useCallback, useEffect, useState } from 'react';

export const ROUTES = ['overview', 'request', 'access', 'approvals', 'profiles', 'help'] as const;
export type Route = (typeof ROUTES)[number];

function routeFromHash(hash: string): Route {
  const candidate = hash.replace(/^#\/?/, '');
  return (ROUTES as readonly string[]).includes(candidate) ? (candidate as Route) : 'overview';
}

/** useHashRoute keeps the current view in the URL hash, so views are linkable and the back button works. */
export function useHashRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState<Route>(() => routeFromHash(window.location.hash));

  useEffect(() => {
    const onChange = () => setRoute(routeFromHash(window.location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const navigate = useCallback((next: Route) => {
    window.location.hash = `/${next}`;
  }, []);

  return [route, navigate];
}
