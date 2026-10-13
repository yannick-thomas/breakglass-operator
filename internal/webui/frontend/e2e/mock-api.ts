import type { Page, Route } from '@playwright/test';
import type { AccessEntry, Me, Profile } from '../src/api/types';

/**
 * MockBackend emulates the BFF API with in-memory state, so browser tests can
 * walk through complete flows without a cluster. It records every write.
 */
export class MockBackend {
  me: Me = { username: 'oidc:jane@example.com', displayName: 'Jane Doe', groups: ['oncall'], devMode: false };
  profiles: Profile[] = [
    {
      name: 'production-pod-observer-approval',
      targetNamespace: 'production',
      maxDuration: '1h',
      deliveryMode: 'ApprovalRequired',
      roleRef: 'breakglass-pod-observer',
      description: 'Pods, Events und Logs in production lesen',
      isReady: true,
    },
    {
      name: 'staging-pod-observer',
      targetNamespace: 'staging',
      maxDuration: '2h',
      deliveryMode: 'SelfService',
      roleRef: 'breakglass-pod-observer',
      description: 'Pods, Events und Logs in staging lesen',
      isReady: true,
    },
  ];
  mine: AccessEntry[] = [];
  pending: AccessEntry[] = [];
  writes: { path: string; body: unknown }[] = [];
  private counter = 0;

  static entry(overrides: Partial<AccessEntry>): AccessEntry {
    return {
      kind: 'Request',
      name: 'bgr-x',
      accessProfile: 'production-pod-observer-approval',
      targetNamespace: 'production',
      requester: 'oidc:jane@example.com',
      duration: '30m',
      reason: 'INC-1092 Datenbankverbindungen prüfen',
      phase: 'Pending',
      createdAt: new Date(Date.now() - 4 * 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 11 * 60_000).toISOString(),
      sessionRevoked: false,
      canRevoke: false,
      canApprove: false,
      ...overrides,
    };
  }

  async install(page: Page) {
    await page.route('**/api/v1/**', (route) => this.handle(route));
    await page.route('**/auth/logout', (route) => {
      this.writes.push({ path: '/auth/logout', body: null });
      return route.fulfill({ json: { redirect: '/logged-out.html' } });
    });
  }

  private async handle(route: Route) {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();

    if (method === 'POST') {
      // The real BFF rejects anything else; keep the client honest.
      if (request.headers()['content-type'] !== 'application/json') {
        return route.fulfill({ status: 415, json: { error: 'Content-Type application/json erforderlich.' } });
      }
      const body = request.postDataJSON() as Record<string, string>;
      this.writes.push({ path, body });

      if (path === '/api/v1/requests') {
        const profile = this.profiles.find((p) => p.name === body.accessProfile);
        const selfService = profile?.deliveryMode === 'SelfService';
        const created = MockBackend.entry({
          kind: selfService ? 'Session' : 'Request',
          name: `${selfService ? 'bgs' : 'bgr'}-new${++this.counter}`,
          accessProfile: body.accessProfile,
          targetNamespace: profile?.targetNamespace ?? '',
          duration: body.duration,
          reason: body.reason,
          phase: 'Pending',
          createdAt: new Date().toISOString(),
        });
        this.mine.unshift(created);
        return route.fulfill({ status: 201, json: created });
      }
      if (path === '/api/v1/approvals') {
        this.pending = this.pending.filter((p) => p.name !== body.requestName);
        return route.fulfill({ status: 201, json: { status: 'decision_recorded' } });
      }
      const revoke = path.match(/^\/api\/v1\/sessions\/([^/]+)\/revoke$/);
      if (revoke) {
        const entry = this.mine.find((e) => e.sessionName === decodeURIComponent(revoke[1] ?? ''));
        if (entry) Object.assign(entry, { sessionPhase: 'Revoked', sessionRevoked: true, canRevoke: false });
        return route.fulfill({ json: { status: 'revoked' } });
      }
    }

    switch (path) {
      case '/api/v1/me':
        return route.fulfill({ json: this.me });
      case '/api/v1/profiles':
        return route.fulfill({ json: this.profiles });
      case '/api/v1/my-requests':
        return route.fulfill({ json: this.mine });
      case '/api/v1/approvals/pending':
        return route.fulfill({ json: this.pending });
      default:
        return route.fulfill({ status: 404, json: { error: 'Nicht gefunden.' } });
    }
  }
}

export function activeEntry(): AccessEntry {
  return MockBackend.entry({
    name: 'bgr-active1',
    phase: 'SessionCreated',
    sessionName: 'breakglass-request-1a2b',
    sessionPhase: 'Active',
    sessionCreatedAt: new Date(Date.now() - 60_000).toISOString(),
    sessionExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
    canRevoke: true,
    approvalDecision: 'Approved',
    approver: 'oidc:max@example.com',
    approvalCreatedAt: new Date(Date.now() - 90_000).toISOString(),
  });
}

export function pendingApproval(): AccessEntry {
  return MockBackend.entry({
    name: 'bgr-other1',
    requester: 'oidc:max@example.com',
    canApprove: true,
  });
}
