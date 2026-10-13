import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { AccessEntry } from '../api/types';
import { Toaster } from '../components/Toaster';
import { useStatusNotifications } from '../hooks/useStatusNotifications';
import { entry, renderWithApp, resource } from '../test/render';
import { Overview } from './Overview';

const active = entry({
  name: 'bgr-active',
  requester: 'oidc:jane@example.com',
  phase: 'SessionCreated',
  sessionName: 'breakglass-request-1a2b',
  sessionPhase: 'Active',
  sessionCreatedAt: new Date(Date.now() - 5 * 60_000).toISOString(),
  sessionExpiresAt: new Date(Date.now() + 25 * 60_000).toISOString(),
  canRevoke: true,
  approver: 'oidc:max@example.com',
});

describe('Overview', () => {
  it('shows a calm idle state with a call to action', async () => {
    const { user, data } = renderWithApp(<Overview />);

    expect(screen.getByRole('heading', { name: 'Kein aktiver Zugriff' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Zugriff anfordern' }));
    expect(data.navigate).toHaveBeenCalledWith('request');
  });

  it('puts active access front and centre with an accessible gauge', async () => {
    const { user } = renderWithApp(<Overview />, { access: resource([active]) });

    expect(screen.getByRole('img', { name: /Zugriff aktiv, noch 25 Minuten/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: active.accessProfile })).toBeInTheDocument();
    expect(screen.getByText('oidc:max@example.com')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Zugriff beenden' }));
    expect(screen.getByRole('alertdialog', { name: 'Zugriff jetzt beenden?' })).toBeInTheDocument();
  });

  it('turns urgent shortly before expiry', () => {
    const ending = { ...active, sessionExpiresAt: new Date(Date.now() + 2 * 60_000).toISOString() };
    renderWithApp(<Overview />, { access: resource([ending]) });
    expect(screen.getByText('Läuft gleich ab')).toBeInTheDocument();
  });

  it('shows a pending request as waiting, not as access', () => {
    renderWithApp(<Overview />, { access: resource([entry({ requester: 'oidc:jane@example.com' })]) });
    const hero = screen.getByRole('region', { name: 'Dein Zugriff' });
    expect(within(hero).getByText('Wartet auf Freigabe')).toBeInTheDocument();
    expect(within(hero).getByText(/Ein Antrag ist noch kein Zugriff/)).toBeInTheDocument();
  });

  it('lets approvers act on waiting requests directly', async () => {
    const { user } = renderWithApp(<Overview />, { approvals: resource([entry({ name: 'bgr-other' })]) });

    const waiting = screen.getByRole('region', { name: 'Wartet auf dich' });
    expect(within(waiting).getByText('oidc:max@example.com')).toBeInTheDocument();
    await user.click(within(waiting).getByRole('button', { name: 'Prüfen' }));
    expect(screen.getByRole('alertdialog', { name: 'Zugriff freigeben' })).toBeInTheDocument();
  });
});

function Probe({ entries }: { entries: AccessEntry[] }) {
  useStatusNotifications(entries);
  return null;
}

describe('useStatusNotifications', () => {
  it('announces a change that happened elsewhere, but not the initial state', () => {
    const pending = entry({ name: 'bgr-1', requester: 'oidc:jane@example.com' });
    const { rerender } = render(
      <Toaster>
        <Probe entries={[pending]} />
      </Toaster>,
    );
    expect(screen.queryByText(/ist jetzt aktiv/)).not.toBeInTheDocument();

    rerender(
      <Toaster>
        <Probe entries={[{ ...pending, phase: 'SessionCreated', sessionPhase: 'Active' }]} />
      </Toaster>,
    );
    expect(screen.getByText(`Zugriff ${pending.accessProfile} ist jetzt aktiv.`)).toBeInTheDocument();
  });
});
