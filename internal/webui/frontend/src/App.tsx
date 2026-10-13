import { useCallback, useEffect, useMemo, useState } from 'react';
import { AppDataContext, type AppData } from './AppContext';
import type { Api } from './api/client';
import type { Me } from './api/types';
import { AppShell } from './components/AppShell';
import { Button } from './components/Button';
import { Loading } from './components/Feedback';
import { useHashRoute } from './hooks/useHashRoute';
import { useResource } from './hooks/useResource';
import { useStatusNotifications } from './hooks/useStatusNotifications';
import { useTheme } from './hooks/useTheme';
import { statusOf } from './lib/status';
import { Approvals } from './views/Approvals';
import { Help } from './views/Help';
import { MyAccess } from './views/MyAccess';
import { Overview } from './views/Overview';
import { Profiles } from './views/Profiles';
import { RequestAccess } from './views/RequestAccess';

const ACCESS_POLL_MS = 15_000;
/** While something is pending or about to change, follow it closely. */
const ACCESS_FAST_POLL_MS = 4_000;
const APPROVALS_POLL_MS = 15_000;

export function App({ api }: { api: Api }) {
  const me = useResource(api.me);

  if (me.loading && !me.data) {
    return (
      <div className="standalone">
        <Loading label="Anmeldung wird geprüft…" />
      </div>
    );
  }
  if (!me.data) {
    return (
      <main className="standalone">
        <div className="standalone-card">
          <h1>BreakGlass ist gerade nicht erreichbar</h1>
          <p role="alert">{me.error?.message ?? 'Unbekannter Fehler.'}</p>
          <p>
            <Button variant="primary" onPress={() => void me.reload()}>
              Erneut versuchen
            </Button>
          </p>
        </div>
      </main>
    );
  }
  return <SignedIn api={api} me={me.data} />;
}

function SignedIn({ api, me }: { api: Api; me: Me }) {
  const [route, navigate] = useHashRoute();
  const [theme, setTheme] = useTheme();
  const profiles = useResource(api.profiles);
  const [fastPoll, setFastPoll] = useState(false);
  const access = useResource(api.myAccess, fastPoll ? ACCESS_FAST_POLL_MS : ACCESS_POLL_MS);
  const approvals = useResource(api.pendingApprovals, APPROVALS_POLL_MS);

  useEffect(() => {
    setFastPoll((access.data ?? []).some((e) => statusOf(e).group === 'open'));
  }, [access.data]);
  useStatusNotifications(access.data);

  const data = useMemo<AppData>(
    () => ({ api, me, profiles, access, approvals, navigate }),
    [api, me, profiles, access, approvals, navigate],
  );

  const activeCount = (access.data ?? []).filter((e) => statusOf(e).group === 'active').length;

  const logout = useCallback(async () => {
    let target = '/logged-out.html';
    try {
      target = await api.logout();
    } finally {
      window.location.assign(target);
    }
  }, [api]);

  return (
    <AppDataContext.Provider value={data}>
      <AppShell
        me={me}
        route={route}
        activeCount={activeCount}
        pendingApprovalCount={approvals.data?.length ?? 0}
        updatedAt={access.updatedAt}
        connectionError={Boolean(access.error)}
        theme={theme}
        onThemeChange={setTheme}
        onLogout={() => void logout()}
      >
        {route === 'overview' && <Overview />}
        {route === 'request' && <RequestAccess />}
        {route === 'access' && <MyAccess />}
        {route === 'approvals' && <Approvals />}
        {route === 'profiles' && <Profiles />}
        {route === 'help' && <Help />}
      </AppShell>
    </AppDataContext.Provider>
  );
}
