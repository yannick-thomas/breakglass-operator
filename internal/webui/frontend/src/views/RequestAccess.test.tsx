import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import { entry, mockApi, profile, renderWithApp, resource } from '../test/render';
import { RequestAccess } from './RequestAccess';

const profiles = resource([
  profile(),
  profile({ name: 'staging-self-service', targetNamespace: 'staging', deliveryMode: 'SelfService', maxDuration: '2h' }),
  profile({ name: 'broken', isReady: false }),
]);

async function fillForm(user: ReturnType<typeof renderWithApp>['user'], duration = '45m') {
  await user.click(screen.getByRole('radio', { name: /production-pod-observer-approval/ }));
  const durationField = screen.getByRole('textbox', { name: /Dauer/ });
  await user.clear(durationField);
  await user.type(durationField, duration);
  await user.type(screen.getByRole('textbox', { name: /Begründung/ }), '  INC-1092 Datenbank prüfen  ');
}

async function findSubmitError() {
  const title = await screen.findByText('Der Antrag wurde nicht angenommen.');
  return title.closest('[role="alert"]');
}

describe('RequestAccess', () => {
  it('validates before the review step', async () => {
    const { user } = renderWithApp(<RequestAccess />, { profiles });

    await user.click(screen.getByRole('button', { name: 'Weiter zur Prüfung' }));

    expect(screen.getByText('Wähle ein Profil aus.')).toBeInTheDocument();
    expect(screen.getByText(/mindestens 5 Zeichen/)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Angaben prüfen' })).not.toBeInTheDocument();
  });

  it('rejects a duration above the profile maximum', async () => {
    const { user } = renderWithApp(<RequestAccess />, { profiles });
    await fillForm(user, '3h');
    await user.click(screen.getByRole('button', { name: 'Weiter zur Prüfung' }));

    expect(screen.getByText('Zu lang: Dieses Profil erlaubt höchstens 1 Std.')).toBeInTheDocument();
  });

  it('does not offer a profile that is not ready', () => {
    renderWithApp(<RequestAccess />, { profiles });
    expect(screen.getByRole('radio', { name: /broken/ })).toBeDisabled();
  });

  it('reviews, then submits trimmed values once', async () => {
    const api = mockApi({ createAccess: vi.fn(async () => entry({ name: 'bgr-new01' })) });
    const { user, data } = renderWithApp(<RequestAccess />, { profiles, api });

    await fillForm(user);
    await user.click(screen.getByRole('button', { name: 'Weiter zur Prüfung' }));

    expect(screen.getByRole('heading', { name: 'Angaben prüfen' })).toBeInTheDocument();
    expect(screen.getByText(/Ein Antrag ist noch kein Zugriff/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Verbindlich beantragen' }));

    expect(api.createAccess).toHaveBeenCalledTimes(1);
    expect(api.createAccess).toHaveBeenCalledWith({
      accessProfile: 'production-pod-observer-approval',
      duration: '45m',
      reason: 'INC-1092 Datenbank prüfen',
    });
    expect(await screen.findByRole('heading', { name: 'Antrag eingereicht' })).toBeInTheDocument();
    expect(screen.getByText('bgr-new01')).toBeInTheDocument();
    expect(data.access.reload).toHaveBeenCalled();
  });

  it('warns about an unclear outcome instead of retrying', async () => {
    const api = mockApi({ createAccess: vi.fn(async () => Promise.reject(new ApiError('Gateway Timeout', 504))) });
    const { user } = renderWithApp(<RequestAccess />, { profiles, api });

    await fillForm(user);
    await user.click(screen.getByRole('button', { name: 'Weiter zur Prüfung' }));
    await user.click(screen.getByRole('button', { name: 'Verbindlich beantragen' }));

    expect(await findSubmitError()).toHaveTextContent(/bevor du ihn erneut stellst/);
    expect(api.createAccess).toHaveBeenCalledTimes(1);
  });

  it('shows an admission denial without the retry warning', async () => {
    const api = mockApi({
      createAccess: vi.fn(async () => Promise.reject(new ApiError('requester is not authorized to use AccessProfile', 403))),
    });
    const { user } = renderWithApp(<RequestAccess />, { profiles, api });

    await fillForm(user);
    await user.click(screen.getByRole('button', { name: 'Weiter zur Prüfung' }));
    await user.click(screen.getByRole('button', { name: 'Verbindlich beantragen' }));

    const alert = await findSubmitError();
    expect(alert).toHaveTextContent('requester is not authorized');
    expect(alert).not.toHaveTextContent(/erneut stellst/);
  });

  it('explains when no profile is available', () => {
    renderWithApp(<RequestAccess />, { profiles: resource([]) });
    expect(screen.getByText('Für deine Identität ist kein Profil freigegeben.')).toBeInTheDocument();
  });
});
