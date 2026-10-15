import { useEffect, useRef, type ReactNode } from 'react';
import { Radio, RadioGroup } from 'react-aria-components';
import type { Me } from '../api/types';
import type { Route } from '../hooks/useHashRoute';
import { useNow } from '../hooks/useNow';
import type { ThemePreference } from '../hooks/useTheme';
import { BrandMark, Wordmark } from './Brand';
import { Button } from './Button';
import { Icon, type IconName } from './Icon';
import styles from './AppShell.module.css';

interface NavItem {
  route: Route;
  label: string;
  icon: IconName;
  count?: number;
  countLabel?: string;
  attention?: boolean;
}

export interface AppShellProps {
  me: Me;
  route: Route;
  activeCount: number;
  pendingApprovalCount: number;
  /** Time of the last successful refresh of the person's access. */
  updatedAt: number | undefined;
  connectionError: boolean;
  theme: ThemePreference;
  onThemeChange: (theme: ThemePreference) => void;
  onLogout: () => void;
  children: ReactNode;
}

export function AppShell({
  me,
  route,
  activeCount,
  pendingApprovalCount,
  updatedAt,
  connectionError,
  theme,
  onThemeChange,
  onLogout,
  children,
}: AppShellProps) {
  const mainRef = useRef<HTMLElement>(null);
  const previousRoute = useRef(route);

  // Move focus to the new view's heading so keyboard and screen-reader users
  // land on the content after navigating, as on a page load.
  useEffect(() => {
    // StrictMode replays mount effects. Only an actual route change should
    // move focus; initial loads must leave the skip link first in tab order.
    if (previousRoute.current === route) return;
    previousRoute.current = route;
    mainRef.current?.querySelector<HTMLElement>('h1')?.focus();
  }, [route]);

  const nav: NavItem[] = [
    { route: 'overview', label: 'Lagebild', icon: 'gauge' },
    { route: 'request', label: 'Zugriff anfordern', icon: 'bolt' },
    { route: 'access', label: 'Meine Zugriffe', icon: 'list', count: activeCount, countLabel: 'aktiv' },
    {
      route: 'approvals',
      label: 'Freigaben',
      icon: 'shield',
      count: pendingApprovalCount,
      countLabel: 'offen',
      attention: pendingApprovalCount > 0,
    },
    { route: 'profiles', label: 'Profile', icon: 'catalog' },
    { route: 'help', label: 'Hilfe', icon: 'help' },
  ];

  const displayName = me.displayName || me.username;

  return (
    <div className={styles.shell}>
      <a className={styles.skipLink} href="#main">
        Zum Inhalt springen
      </a>

      <header className={styles.header}>
        <a className={styles.brand} href="#/overview" aria-label="BreakGlass Lagebild">
          <BrandMark size={30} className={styles.brandMark} />
          <Wordmark />
        </a>

        <div className={styles.headerEnd}>
          <LiveIndicator updatedAt={updatedAt} error={connectionError} />

          {activeCount > 0 && (
            <a className={styles.activePill} href="#/overview">
              <span className={styles.pulse} aria-hidden="true" />
              {activeCount === 1 ? '1 aktiver Zugriff' : `${activeCount} aktive Zugriffe`}
            </a>
          )}

          <RadioGroup
            aria-label="Darstellung"
            orientation="horizontal"
            value={theme}
            onChange={(value) => onThemeChange(value as ThemePreference)}
            className={styles.themeSwitch}
          >
            {(
              [
                ['dark', 'moon', 'Dunkel'],
                ['light', 'sun', 'Hell'],
                ['system', 'monitor', 'Wie System'],
              ] as const
            ).map(([value, icon, label]) => (
              <Radio key={value} value={value} className={styles.themeOption} aria-label={label}>
                <Icon name={icon} size={15} />
              </Radio>
            ))}
          </RadioGroup>

          <div className={styles.identity}>
            <span className={styles.avatar} aria-hidden="true">
              {displayName.charAt(0).toUpperCase()}
            </span>
            <span className={styles.identityText}>
              <span className={styles.identityName}>{displayName}</span>
              <span className={styles.identityUser} title="Kubernetes-Benutzername">
                {me.username}
              </span>
            </span>
          </div>

          <Button variant="ghost" size="sm" onPress={onLogout} aria-label="Abmelden">
            <Icon name="logout" />
          </Button>
        </div>
      </header>

      {me.devMode && (
        <div className={styles.devBanner} role="note">
          <Icon name="alert" />
          <span>
            <strong>Dev-Modus:</strong> angemeldet mit der kubeconfig-Identität <code>{me.username}</code>. Nicht für
            gemeinsam genutzte Umgebungen.
          </span>
        </div>
      )}

      <div className={styles.body}>
        <nav className={styles.nav} aria-label="Hauptnavigation">
          <ul className={styles.navList}>
            {nav.map((item) => (
              <li key={item.route}>
                <a
                  href={`#/${item.route}`}
                  className={styles.navLink}
                  aria-current={route === item.route ? 'page' : undefined}
                >
                  <Icon name={item.icon} size={17} />
                  <span className={styles.navLabel}>{item.label}</span>
                  {item.count ? (
                    <span className={`${styles.navCount} ${item.attention ? styles.navCountAttention : ''}`}>
                      {item.count}
                      <span className="visually-hidden"> {item.countLabel}</span>
                    </span>
                  ) : null}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        <main id="main" ref={mainRef} className={styles.main}>
          {children}
        </main>
      </div>
    </div>
  );
}

/**
 * LiveIndicator shows that the view follows the cluster. It is deliberately
 * not a live region: it changes every second and would drown out real news.
 */
function LiveIndicator({ updatedAt, error }: { updatedAt: number | undefined; error: boolean }) {
  const now = useNow();
  if (error) {
    return (
      <span className={`${styles.live} ${styles.liveError}`}>
        <span className={styles.liveDot} aria-hidden="true" />
        Verbindung gestört
      </span>
    );
  }
  const seconds = updatedAt ? Math.max(0, Math.round((now - updatedAt) / 1000)) : undefined;
  return (
    <span className={styles.live} title="Die Ansicht aktualisiert sich automatisch">
      <span className={styles.liveDot} aria-hidden="true" />
      Live
      {seconds !== undefined && <span className={styles.liveAge}>· vor {seconds} s</span>}
    </span>
  );
}
