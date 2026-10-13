import { render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';
import { vi } from 'vitest';
import { AppDataContext, type AppData } from '../AppContext';
import type { Api } from '../api/client';
import type { AccessEntry, Me, Profile } from '../api/types';
import { Toaster } from '../components/Toaster';
import type { Resource } from '../hooks/useResource';

export const me: Me = { username: 'oidc:jane@example.com', displayName: 'Jane', groups: ['oncall'], devMode: false };

export function profile(overrides: Partial<Profile> = {}): Profile {
  return {
    name: 'production-pod-observer-approval',
    targetNamespace: 'production',
    maxDuration: '1h',
    deliveryMode: 'ApprovalRequired',
    roleRef: 'breakglass-pod-observer',
    description: 'Pods, Events und Logs in production lesen',
    isReady: true,
    ...overrides,
  };
}

export function entry(overrides: Partial<AccessEntry> = {}): AccessEntry {
  return {
    kind: 'Request',
    name: 'bgr-abc12',
    accessProfile: 'production-pod-observer-approval',
    targetNamespace: 'production',
    requester: 'oidc:max@example.com',
    duration: '30m',
    reason: 'INC-1092 Datenbankverbindungen prüfen',
    phase: 'Pending',
    createdAt: new Date(Date.now() - 5 * 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    sessionRevoked: false,
    canRevoke: false,
    canApprove: true,
    ...overrides,
  };
}

export function resource<T>(data: T): Resource<T> {
  return { data, error: undefined, loading: false, updatedAt: Date.now(), reload: vi.fn(async () => undefined) };
}

export function mockApi(overrides: Partial<Api> = {}): Api {
  return {
    me: vi.fn(async () => me),
    profiles: vi.fn(async () => []),
    myAccess: vi.fn(async () => []),
    pendingApprovals: vi.fn(async () => []),
    createAccess: vi.fn(async () => entry()),
    revokeSession: vi.fn(async () => undefined),
    decide: vi.fn(async () => undefined),
    logout: vi.fn(async () => '/logged-out.html'),
    ...overrides,
  };
}

export function renderWithApp(ui: ReactElement, data: Partial<AppData> = {}) {
  const value: AppData = {
    api: mockApi(),
    me,
    profiles: resource<Profile[]>([]),
    access: resource<AccessEntry[]>([]),
    approvals: resource<AccessEntry[]>([]),
    navigate: vi.fn(),
    ...data,
  };
  const user = userEvent.setup();
  const result = render(
    <Toaster>
      <AppDataContext.Provider value={value}>{ui}</AppDataContext.Provider>
    </Toaster>,
  );
  return { ...result, user, data: value };
}
