import { describe, expect, it } from 'vitest';
import { entry } from '../test/render';
import { statusOf } from './status';

describe('statusOf', () => {
  it('treats a pending request as open, never as access', () => {
    const status = statusOf(entry({ phase: 'Pending' }));
    expect(status.group).toBe('open');
    expect(status.description).toContain('noch kein Zugriff');
  });

  it('prefers the session phase once a session exists', () => {
    expect(statusOf(entry({ phase: 'SessionCreated', sessionPhase: 'Active' })).group).toBe('active');
    expect(statusOf(entry({ phase: 'SessionCreated', sessionPhase: 'Revoked' })).group).toBe('history');
  });

  it('distinguishes an expired request from an expired session', () => {
    expect(statusOf(entry({ phase: 'Expired' })).label).toBe('Verfallen');
    expect(statusOf(entry({ phase: 'SessionCreated', sessionPhase: 'Expired' })).label).toBe('Abgelaufen');
  });

  it('flags a suspended session as a security event', () => {
    const status = statusOf(entry({ sessionPhase: 'Suspended' }));
    expect(status.tone).toBe('danger');
    expect(status.description).toContain('Eine automatische Reaktivierung gibt es nicht.');
  });
});
