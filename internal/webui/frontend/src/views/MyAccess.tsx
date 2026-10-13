import { useMemo, useState } from 'react';
import { Tab, TabList, TabPanel, Tabs } from 'react-aria-components';
import { useAppData } from '../AppContext';
import { ApiError } from '../api/client';
import type { AccessEntry } from '../api/types';
import { Button } from '../components/Button';
import { Countdown } from '../components/Countdown';
import { AppDialog } from '../components/Dialog';
import { EmptyState, Loading, Notice, StatusBadge } from '../components/Feedback';
import { Icon } from '../components/Icon';
import { useNotify } from '../components/Toaster';
import { useNow } from '../hooks/useNow';
import { formatGoDuration, formatRelative } from '../lib/format';
import { statusOf, type StatusGroup } from '../lib/status';
import { PageHeader } from './PageHeader';
import { Timeline } from './Timeline';
import page from './page.module.css';
import styles from './MyAccess.module.css';

const TABS: { id: StatusGroup; label: string; empty: string }[] = [
  { id: 'active', label: 'Aktiv', empty: 'Du hast derzeit keinen aktiven Zugriff.' },
  { id: 'open', label: 'Offen', empty: 'Keine offenen Anträge.' },
  { id: 'history', label: 'Verlauf', empty: 'Noch keine abgeschlossenen Zugriffe.' },
];

export function MyAccess() {
  const { access, navigate } = useAppData();
  const now = useNow();
  const [selectedTab, setSelectedTab] = useState<StatusGroup | null>(null);
  const [detail, setDetail] = useState<AccessEntry>();
  const [revoking, setRevoking] = useState<AccessEntry>();

  const groups = useMemo(() => {
    const result: Record<StatusGroup, AccessEntry[]> = { active: [], open: [], history: [] };
    for (const entry of access.data ?? []) result[statusOf(entry).group].push(entry);
    return result;
  }, [access.data]);

  // Until the person picks a tab, show the most relevant non-empty group.
  const tab: StatusGroup =
    selectedTab ?? (groups.active.length ? 'active' : groups.open.length ? 'open' : groups.history.length ? 'history' : 'active');

  // Keep the dialog in sync with polled data.
  const current = detail && access.data?.find((e) => e.name === detail.name);

  return (
    <div className={page.page}>
      <PageHeader
        title="Meine Zugriffe"
        description="Deine Anträge und Sessions. Beende einen Zugriff, sobald du ihn nicht mehr brauchst."
        actions={
          <Button variant="ghost" size="sm" onPress={() => void access.reload()}>
            <Icon name="refresh" />
            Aktualisieren
          </Button>
        }
      />

      {access.error && (
        <Notice tone="danger" title="Zugriffe konnten nicht geladen werden.">
          {access.error.message}
        </Notice>
      )}

      {access.loading && !access.data ? (
        <Loading label="Zugriffe werden geladen…" />
      ) : (
        <Tabs selectedKey={tab} onSelectionChange={(key) => setSelectedTab(key as StatusGroup)}>
          <TabList aria-label="Zugriffe filtern" className={styles.tabList}>
            {TABS.map((t) => (
              <Tab key={t.id} id={t.id} className={styles.tab}>
                {t.label}
                <span className={styles.tabCount}>{groups[t.id].length}</span>
              </Tab>
            ))}
          </TabList>
          {TABS.map((t) => (
            <TabPanel key={t.id} id={t.id} className={styles.panel}>
              {groups[t.id].length === 0 ? (
                <div className={page.card}>
                  <EmptyState icon="list" title={t.empty}>
                    {t.id !== 'history' && (
                      <Button variant="primary" size="sm" onPress={() => navigate('request')}>
                        Zugriff anfordern
                      </Button>
                    )}
                  </EmptyState>
                </div>
              ) : (
                <ul className={page.list}>
                  {groups[t.id].map((entry) => (
                    <li key={entry.name}>
                      <AccessRow
                        entry={entry}
                        now={now}
                        onDetails={() => setDetail(entry)}
                        onRevoke={() => setRevoking(entry)}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </TabPanel>
          ))}
        </Tabs>
      )}

      {current && (
        <AccessDetails
          entry={current}
          now={now}
          onClose={() => setDetail(undefined)}
          onRevoke={() => {
            setDetail(undefined);
            setRevoking(current);
          }}
        />
      )}

      {revoking && (
        <RevokeDialog
          entry={revoking}
          onClose={() => setRevoking(undefined)}
          onRevoked={() => {
            setRevoking(undefined);
            void access.reload();
          }}
        />
      )}
    </div>
  );
}

function AccessRow({ entry, now, onDetails, onRevoke }: { entry: AccessEntry; now: number; onDetails: () => void; onRevoke: () => void }) {
  const status = statusOf(entry);
  const revocable = entry.canRevoke && Boolean(entry.sessionName);
  return (
    <article className={`${page.card} ${styles.row}`} aria-labelledby={`row-${entry.name}`}>
      <div className={styles.rowMain}>
        <div className={styles.rowTitle}>
          <h2 id={`row-${entry.name}`} className={styles.rowName}>
            {entry.accessProfile}
          </h2>
          <StatusBadge tone={status.tone} label={status.label} />
        </div>
        <dl className={page.factsInline}>
          <div>
            <dt>Namespace</dt>
            <dd className={page.mono}>{entry.targetNamespace || '–'}</dd>
          </div>
          <div>
            <dt>Dauer</dt>
            <dd>{formatGoDuration(entry.duration)}</dd>
          </div>
          {status.group === 'active' && entry.sessionExpiresAt ? (
            <div>
              <dt>Verbleibend</dt>
              <dd>
                <Countdown until={entry.sessionExpiresAt} now={now} />
              </dd>
            </div>
          ) : (
            <div>
              <dt>Erstellt</dt>
              <dd>{formatRelative(entry.createdAt, now)}</dd>
            </div>
          )}
          <div>
            <dt>Referenz</dt>
            <dd className={page.mono}>{entry.name}</dd>
          </div>
        </dl>
      </div>
      <div className={styles.rowActions}>
        <Button size="sm" onPress={onDetails} aria-label={`Details zu ${entry.name}`}>
          Details
        </Button>
        {revocable && (
          <Button size="sm" variant="danger" onPress={onRevoke} aria-label={`Zugriff ${entry.name} beenden`}>
            Beenden
          </Button>
        )}
      </div>
    </article>
  );
}

export function AccessDetails({ entry, now, onClose, onRevoke }: { entry: AccessEntry; now: number; onClose: () => void; onRevoke: () => void }) {
  const notify = useNotify();
  const status = statusOf(entry);
  const revocable = entry.canRevoke && Boolean(entry.sessionName);
  const command = `kubectl get pods -n ${entry.targetNamespace}`;

  return (
    <AppDialog
      title={entry.accessProfile}
      isOpen
      onOpenChange={(open) => !open && onClose()}
      size="lg"
      footer={
        <>
          {revocable && (
            <Button variant="danger" onPress={onRevoke}>
              Zugriff beenden
            </Button>
          )}
          <Button onPress={onClose}>Schließen</Button>
        </>
      }
    >
      <Notice tone={status.tone} title={status.label}>
        {status.description}
      </Notice>
      <dl className={page.facts}>
        <dt>Referenz</dt>
        <dd className={page.mono}>{entry.name}</dd>
        <dt>Art</dt>
        <dd>{entry.kind === 'Request' ? 'Antrag mit Freigabe' : 'Self-Service'}</dd>
        <dt>Namespace</dt>
        <dd className={page.mono}>{entry.targetNamespace || '–'}</dd>
        <dt>Dauer</dt>
        <dd>{formatGoDuration(entry.duration)}</dd>
        {status.group === 'active' && entry.sessionExpiresAt && (
          <>
            <dt>Verbleibend</dt>
            <dd>
              <Countdown until={entry.sessionExpiresAt} now={now} />
            </dd>
          </>
        )}
        <dt>Begründung</dt>
        <dd className={page.reason}>{entry.reason}</dd>
      </dl>

      {status.group === 'active' && entry.targetNamespace && (
        <div className={styles.cli}>
          <p className={page.sectionTitle}>Loslegen</p>
          <div className={page.code}>
            <code>{command}</code>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Befehl kopieren"
              onPress={async () => {
                try {
                  await navigator.clipboard.writeText(command);
                  notify('Befehl kopiert.', 'info');
                } catch {
                  notify('Kopieren war nicht möglich.', 'danger');
                }
              }}
            >
              <Icon name="copy" />
            </Button>
          </div>
        </div>
      )}

      <div>
        <p className={page.sectionTitle}>Verlauf</p>
        <Timeline entry={entry} />
      </div>
    </AppDialog>
  );
}

export function RevokeDialog({ entry, onClose, onRevoked }: { entry: AccessEntry; onClose: () => void; onRevoked: () => void }) {
  const { api } = useAppData();
  const notify = useNotify();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  async function revoke() {
    if (!entry.sessionName) return;
    setPending(true);
    setError(undefined);
    try {
      await api.revokeSession(entry.sessionName);
      notify(`Zugriff ${entry.name} wird beendet.`, 'success');
      onRevoked();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setPending(false);
    }
  }

  return (
    <AppDialog
      title="Zugriff jetzt beenden?"
      role="alertdialog"
      isDismissable={false}
      isOpen
      onOpenChange={(open) => !open && !pending && onClose()}
      footer={
        <>
          <Button onPress={onClose} isDisabled={pending}>
            Abbrechen
          </Button>
          <Button variant="danger" onPress={revoke} isPending={pending} isDisabled={pending}>
            {pending ? 'Wird beendet…' : 'Zugriff beenden'}
          </Button>
        </>
      }
    >
      <p>
        Die Berechtigung für <strong>{entry.accessProfile}</strong> im Namespace{' '}
        <span className={page.mono}>{entry.targetNamespace || '–'}</span> wird sofort entfernt. Das lässt sich nicht
        rückgängig machen; für erneuten Zugriff ist ein neuer Antrag nötig.
      </p>
      {error && (
        <Notice tone="danger" title="Der Zugriff wurde nicht beendet." urgent>
          {error}
        </Notice>
      )}
    </AppDialog>
  );
}
