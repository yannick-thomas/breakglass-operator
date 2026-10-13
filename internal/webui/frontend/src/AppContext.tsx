import { createContext, useContext } from 'react';
import type { Api } from './api/client';
import type { AccessEntry, Me, Profile } from './api/types';
import type { Route } from './hooks/useHashRoute';
import type { Resource } from './hooks/useResource';

export interface AppData {
  api: Api;
  me: Me;
  profiles: Resource<Profile[]>;
  access: Resource<AccessEntry[]>;
  approvals: Resource<AccessEntry[]>;
  navigate: (route: Route) => void;
}

export const AppDataContext = createContext<AppData | null>(null);

export function useAppData(): AppData {
  const data = useContext(AppDataContext);
  if (!data) throw new Error('useAppData must be used inside AppDataContext');
  return data;
}
