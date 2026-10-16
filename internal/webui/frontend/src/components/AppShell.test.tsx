import { render, screen } from '@testing-library/react';
import { StrictMode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { me } from '../test/render';
import { AppShell, type AppShellProps } from './AppShell';

describe('route focus', () => {
  it('preserves initial keyboard entry in StrictMode and focuses later navigations', () => {
    const props: Omit<AppShellProps, 'children'> = {
      me, route: 'request', activeCount: 0, pendingApprovalCount: 0,
      updatedAt: undefined, connectionError: false, theme: 'dark',
      onThemeChange: vi.fn(), onLogout: vi.fn(),
    };
    const view = (route: AppShellProps['route']) => (
      <StrictMode>
        <AppShell {...props} route={route}>
          <h1 tabIndex={-1}>{route}</h1>
        </AppShell>
      </StrictMode>
    );
    const { rerender } = render(view('request'));
    expect(screen.getByRole('heading', { level: 1 })).not.toHaveFocus();
    rerender(view('help'));
    expect(screen.getByRole('heading', { name: 'help' })).toHaveFocus();
  });
});
