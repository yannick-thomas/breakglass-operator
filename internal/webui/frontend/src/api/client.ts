import type { AccessEntry, CreateAccessInput, Decision, Me, Profile } from './types';

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** The session ended or Kubernetes rejected the credential; a login redirect is in progress. */
export class SessionExpiredError extends ApiError {
  constructor() {
    super('Anmeldung erforderlich.', 401);
    this.name = 'SessionExpiredError';
  }
}

export interface Api {
  me(): Promise<Me>;
  profiles(): Promise<Profile[]>;
  myAccess(): Promise<AccessEntry[]>;
  pendingApprovals(): Promise<AccessEntry[]>;
  createAccess(input: CreateAccessInput): Promise<AccessEntry>;
  revokeSession(sessionName: string): Promise<void>;
  decide(requestName: string, decision: Decision, comment: string): Promise<void>;
  logout(): Promise<string>;
}

export type Navigate = (url: string) => void;

interface RequestOptions {
  method?: 'GET' | 'POST';
  body?: unknown;
}

/**
 * createApi talks to the same-origin BFF. Unsafe requests are JSON, which the
 * BFF requires for CSRF protection. Nothing is retried automatically: an
 * unclear outcome of a write must never create a second request.
 */
export function createApi(navigate: Navigate = (url) => window.location.assign(url)): Api {
  async function request<T>(path: string, { method = 'GET', body }: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    let payload: string | undefined;
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body ?? {});
    }

    let res: Response;
    try {
      res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin' });
    } catch {
      throw new ApiError('Der BreakGlass-Server ist nicht erreichbar.', 0);
    }

    if (res.status === 401) {
      navigate('/auth/login');
      throw new SessionExpiredError();
    }

    let data: unknown = null;
    try {
      data = await res.json();
    } catch {
      // Empty or non-JSON body; handled below.
    }
    if (!res.ok) {
      const message =
        data && typeof data === 'object' && 'error' in data && typeof data.error === 'string'
          ? data.error
          : `Die Anfrage ist fehlgeschlagen (HTTP ${res.status}).`;
      throw new ApiError(message, res.status);
    }
    return data as T;
  }

  return {
    me: () => request<Me>('/api/v1/me'),
    profiles: () => request<Profile[]>('/api/v1/profiles'),
    myAccess: () => request<AccessEntry[]>('/api/v1/my-requests'),
    pendingApprovals: () => request<AccessEntry[]>('/api/v1/approvals/pending'),
    createAccess: (input) => request<AccessEntry>('/api/v1/requests', { method: 'POST', body: input }),
    revokeSession: async (sessionName) => {
      await request(`/api/v1/sessions/${encodeURIComponent(sessionName)}/revoke`, { method: 'POST' });
    },
    decide: async (requestName, decision, comment) => {
      await request('/api/v1/approvals', { method: 'POST', body: { requestName, decision, comment } });
    },
    logout: async () => {
      const data = await request<{ redirect?: string }>('/auth/logout', { method: 'POST' });
      return safeRedirect(data?.redirect);
    },
  };
}

/** safeRedirect only follows same-origin paths or https URLs (the IdP logout endpoint). */
export function safeRedirect(target: string | undefined): string {
  const fallback = '/logged-out.html';
  if (!target) return fallback;
  if (target.startsWith('/') && !target.startsWith('//')) return target;
  try {
    return new URL(target).protocol === 'https:' ? target : fallback;
  } catch {
    return fallback;
  }
}
