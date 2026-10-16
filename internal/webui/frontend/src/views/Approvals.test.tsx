import { screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import { entry, mockApi, renderWithApp, resource } from '../test/render';
import { Approvals } from './Approvals';

describe('Approvals', () => {
  it('requires both confirmations before approving', async () => {
    const api = mockApi();
    const approvals = resource([entry()]);
    const { user } = renderWithApp(<Approvals />, { api, approvals });

    await user.click(screen.getByRole('button', { name: 'Prüfen und freigeben' }));
    const dialog = screen.getByRole('alertdialog', { name: 'Zugriff freigeben' });
    const confirm = within(dialog).getByRole('button', { name: 'Verbindlich freigeben' });

    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox', { name: /nicht die antragstellende Person/ }));
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox', { name: /geprüft/ }));
    expect(confirm).toBeEnabled();

    await user.type(within(dialog).getByRole('textbox', { name: /Kommentar/ }), ' passt ');
    await user.click(confirm);

    expect(api.decide).toHaveBeenCalledWith('breakglass-access', 'bgr-abc12', 'Approved', 'passt');
    expect(approvals.reload).toHaveBeenCalled();
    expect(await screen.findByText('Antrag bgr-abc12 freigegeben.')).toBeInTheDocument();
  });

  it('denies without the approval confirmations', async () => {
    const api = mockApi();
    const { user } = renderWithApp(<Approvals />, { api, approvals: resource([entry()]) });

    await user.click(screen.getByRole('button', { name: 'Ablehnen' }));
    const dialog = screen.getByRole('alertdialog', { name: 'Antrag ablehnen' });
    expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Ablehnen' }));

    expect(api.decide).toHaveBeenCalledWith('breakglass-access', 'bgr-abc12', 'Denied', '');
  });

  it('closes and refreshes when someone else decided first', async () => {
    const api = mockApi({
      decide: vi.fn(async () => Promise.reject(new ApiError('Für diesen Antrag wurde bereits entschieden.', 409))),
    });
    const approvals = resource([entry()]);
    const { user } = renderWithApp(<Approvals />, { api, approvals });

    await user.click(screen.getByRole('button', { name: 'Ablehnen' }));
    await user.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Ablehnen' }));

    expect(await screen.findByText('Für diesen Antrag wurde bereits entschieden.')).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(approvals.reload).toHaveBeenCalled();
  });

  it('renders untrusted request text as text, never as markup', () => {
    const payload = '<img src=x onerror="window.__xss=1">';
    renderWithApp(<Approvals />, { approvals: resource([entry({ reason: payload, requester: `<b>${payload}</b>` })]) });

    expect(screen.getByText(payload)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('b')).toBeNull();
  });

  it('shows an empty state', () => {
    renderWithApp(<Approvals />, { approvals: resource([]) });
    expect(screen.getByText('Keine offenen Anträge.')).toBeInTheDocument();
  });
});
