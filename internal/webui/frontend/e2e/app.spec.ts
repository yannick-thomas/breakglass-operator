import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { activeEntry, MockBackend, pendingApproval } from './mock-api';

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

let backend: MockBackend;
let consoleErrors: string[];

test.beforeEach(async ({ page }) => {
  backend = new MockBackend();
  await backend.install(page);
  consoleErrors = [];
  // CSP violations and React errors surface as console errors.
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(err.message));
});

test.afterEach(() => {
  expect(consoleErrors, 'browser console errors').toEqual([]);
});

async function expectAccessible(page: Page) {
  // Measure the settled state, not a fade-in frame at partial opacity.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
}

test('requests approval-required access end to end', async ({ page }) => {
  await page.goto('/#/request');
  await expect(page.getByRole('heading', { level: 1, name: 'Zugriff anfordern' })).toBeVisible();

  // People click the visible label; React Aria keeps the native input visually hidden.
  await page.getByText('production-pod-observer-approval', { exact: true }).click();
  await expect(page.getByRole('radio', { name: /production-pod-observer-approval/ })).toBeChecked();
  await page.getByText('15 Min.', { exact: true }).click();
  await expect(page.getByRole('radio', { name: '15 Min.' })).toBeChecked();
  await page.getByRole('textbox', { name: /Begründung/ }).fill('INC-2001 Pods im production Namespace prüfen');
  await page.getByRole('button', { name: 'Weiter zur Prüfung' }).click();

  await expect(page.getByRole('heading', { name: 'Angaben prüfen' })).toBeVisible();
  await expect(page.getByText('Ein Antrag ist noch kein Zugriff.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Verbindlich beantragen' }).click();

  await expect(page.getByRole('heading', { name: 'Antrag eingereicht' })).toBeVisible();
  expect(backend.writes).toEqual([
    {
      path: '/api/v1/requests',
      body: {
        accessProfile: 'production-pod-observer-approval',
        duration: '15m',
        reason: 'INC-2001 Pods im production Namespace prüfen',
      },
    },
  ]);

  await page.getByRole('button', { name: 'Zu meinen Zugriffen' }).click();
  await expect(page).toHaveURL(/#\/access$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Meine Zugriffe' })).toBeFocused();
  await expect(page.getByRole('tab', { name: /Offen/ })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByText('bgr-new1')).toBeVisible();
});

test('approves another person’s request only after confirming', async ({ page }) => {
  backend.pending = [pendingApproval()];
  await page.goto('/#/approvals');

  await expect(page.getByRole('link', { name: /Freigaben 1 offen/ })).toBeVisible();
  await page.getByRole('button', { name: 'Prüfen und freigeben' }).click();

  const dialog = page.getByRole('alertdialog', { name: 'Zugriff freigeben' });
  await expect(dialog).toBeVisible();
  await expectAccessible(page);

  const confirm = dialog.getByRole('button', { name: 'Verbindlich freigeben' });
  await expect(confirm).toBeDisabled();
  await dialog.getByText('Ich bin nicht die antragstellende Person.').click();
  await expect(confirm).toBeDisabled();
  await dialog.getByText(/Ich habe Profil, Dauer und Begründung geprüft/).click();
  await expect(dialog.getByRole('checkbox', { name: /geprüft/ })).toBeChecked();
  await confirm.click();

  await expect(page.getByText('Antrag bgr-other1 freigegeben.')).toBeVisible();
  await expect(page.getByText('Keine offenen Anträge.')).toBeVisible();
  expect(backend.writes).toEqual([
    { path: '/api/v1/approvals', body: { requestName: 'bgr-other1', decision: 'Approved', comment: '' } },
  ]);
});

test('revokes active access and restores focus after dialogs', async ({ page }) => {
  backend.mine = [activeEntry()];
  await page.goto('/#/access');

  await expect(page.getByRole('link', { name: '1 aktiver Zugriff' })).toBeVisible();

  const details = page.getByRole('button', { name: 'Details zu bgr-active1' });
  await details.click();
  const dialog = page.getByRole('dialog', { name: 'production-pod-observer-approval' });
  await expect(dialog.getByText('kubectl get pods -n production')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(details).toBeFocused();

  await page.getByRole('button', { name: 'Zugriff bgr-active1 beenden' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Zugriff beenden' }).click();

  await expect(page.getByText('Zugriff bgr-active1 wird beendet.')).toBeVisible();
  expect(backend.writes.map((w) => w.path)).toEqual(['/api/v1/sessions/breakglass-request-1a2b/revoke']);
});

test('shows the live situation and follows changes made elsewhere', async ({ page }) => {
  backend.mine = [MockBackend.entry({ name: 'bgr-wait1' })];
  await page.goto('/');

  const hero = page.getByRole('region', { name: 'Dein Zugriff' });
  await expect(hero.getByText('Wartet auf Freigabe')).toBeVisible();
  await expect(page.getByText(/^Live/)).toBeVisible();

  // Another person approves; the controller activates the session.
  Object.assign(backend.mine[0]!, {
    phase: 'SessionCreated',
    sessionName: 'breakglass-request-9z',
    sessionPhase: 'Active',
    sessionCreatedAt: new Date().toISOString(),
    sessionExpiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
    canRevoke: true,
    approver: 'oidc:max@example.com',
  });

  await expect(page.getByText('Zugriff production-pod-observer-approval ist jetzt aktiv.')).toBeVisible({ timeout: 10_000 });
  await expect(hero.getByRole('img', { name: /Zugriff aktiv, noch 30 Minuten/ })).toBeVisible();
  await expect(page.getByRole('link', { name: '1 aktiver Zugriff' })).toBeVisible();
});

test('is operable with the keyboard alone', async ({ page }) => {
  await page.goto('/#/request');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Zum Inhalt springen' })).toBeFocused();

  await page.getByRole('radio', { name: /staging-pod-observer/ }).focus();
  await page.keyboard.press('Space');
  await expect(page.getByRole('radio', { name: /staging-pod-observer/ })).toBeChecked();
  await page.getByRole('textbox', { name: /Begründung/ }).fill('INC-7 Keyboard-only');
  await page.getByRole('textbox', { name: /Begründung/ }).press('Tab');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Angaben prüfen' })).toBeVisible();
});

test('logs out through a same-origin POST', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Abmelden' }).click();
  await expect(page).toHaveURL(/logged-out\.html$/);
  await expect(page.getByRole('heading', { name: 'Du bist abgemeldet' })).toBeVisible();
  expect(backend.writes.map((w) => w.path)).toEqual(['/auth/logout']);
});

for (const theme of ['light', 'dark'] as const) {
  test.describe(`${theme} mode`, () => {
    test.beforeEach(async ({ page }) => {
      await page.addInitScript((value) => window.localStorage.setItem('breakglass-theme', value), theme);
    });

    for (const route of ['overview', 'request', 'access', 'approvals', 'profiles', 'help']) {
      test(`${route} meets WCAG 2.2 AA`, async ({ page }) => {
        backend.mine = [activeEntry(), MockBackend.entry({ name: 'bgr-open1' })];
        backend.pending = [pendingApproval()];
        await page.goto(`/#/${route}`);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        await expectAccessible(page);
      });
    }

    test('logged-out page meets WCAG 2.2 AA', async ({ page }) => {
      await page.goto('/logged-out.html');
      await expectAccessible(page);
    });
  });
}

test('fits a phone screen without horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 740 });
  backend.mine = [activeEntry()];
  backend.pending = [pendingApproval()];
  for (const route of ['overview', 'request', 'access', 'approvals', 'profiles', 'help']) {
    await page.goto(`/#/${route}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, `horizontal overflow on ${route}`).toBeLessThanOrEqual(0);
  }
});
