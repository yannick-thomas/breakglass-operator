import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { entry, mockApi, renderWithApp, resource } from '../test/render';
import { MyAccess } from './MyAccess';

const active = entry({
  name: 'bgr-active',
  requester: 'oidc:jane@example.com',
  phase: 'SessionCreated',
  sessionName: 'breakglass-request-1a2b',
  sessionPhase: 'Active',
  sessionCreatedAt: new Date().toISOString(),
  sessionExpiresAt: new Date(Date.now() + 20 * 60_000).toISOString(),
  canRevoke: true,
  approvalDecision: 'Approved',
  approver: 'oidc:max@example.com',
});
const pending = entry({ name: 'bgr-pending', requester: 'oidc:jane@example.com' });
const ended = entry({ name: 'bgr-ended', phase: 'SessionCreated', sessionName: 's2', sessionPhase: 'Expired' });

describe('MyAccess', () => {
  it('groups entries into tabs and starts with active access', () => {
    renderWithApp(<MyAccess />, { access: resource([active, pending, ended]) });

    expect(screen.getByRole('tab', { name: /Aktiv/ })).toHaveAttribute('aria-selected', 'true');
    const panel = screen.getByRole('tabpanel');
    expect(within(panel).getByText('bgr-active')).toBeInTheDocument();
    expect(within(panel).queryByText('bgr-pending')).not.toBeInTheDocument();
  });

  it('revokes the session after an explicit confirmation', async () => {
    const api = mockApi();
    const access = resource([active]);
    const { user } = renderWithApp(<MyAccess />, { api, access });

    await user.click(screen.getByRole('button', { name: 'Zugriff bgr-active beenden' }));
    const dialog = screen.getByRole('alertdialog', { name: 'Zugriff jetzt beenden?' });
    expect(api.revokeSession).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole('button', { name: 'Zugriff beenden' }));

    expect(api.revokeSession).toHaveBeenCalledWith('breakglass-request-1a2b');
    expect(access.reload).toHaveBeenCalled();
  });

  it('shows the timeline in the details dialog', async () => {
    const { user } = renderWithApp(<MyAccess />, { access: resource([active]) });

    await user.click(screen.getByRole('button', { name: 'Details zu bgr-active' }));
    const dialog = screen.getByRole('dialog');
    const timeline = within(dialog).getByRole('list', { name: 'Verlauf' });
    expect(within(timeline).getByText('Freigegeben')).toBeInTheDocument();
    expect(within(timeline).getByText(/von oidc:max@example.com/)).toBeInTheDocument();
    expect(within(dialog).getByText('kubectl get pods -n production')).toBeInTheDocument();
  });

  it('offers no revoke action for ended access', async () => {
    const { user } = renderWithApp(<MyAccess />, { access: resource([ended]) });
    await user.click(screen.getByRole('tab', { name: /Verlauf/ }));
    expect(screen.queryByRole('button', { name: /beenden/ })).not.toBeInTheDocument();
  });
});
