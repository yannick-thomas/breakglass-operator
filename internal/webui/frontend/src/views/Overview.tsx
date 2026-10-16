import { useMemo, useState } from 'react';
import { useAppData } from '../AppContext';
import { objectKey } from '../api/objectKey';
import type { AccessEntry, Decision } from '../api/types';
import { BrandMark } from '../components/Brand';
import { Button } from '../components/Button';
import { StatusBadge } from '../components/Feedback';
import { Icon } from '../components/Icon';
import { Ring } from '../components/Ring';
import { useNow } from '../hooks/useNow';
import { formatGoDuration, formatRelative, formatRemaining, formatTime, parseDuration } from '../lib/format';
import { statusOf } from '../lib/status';
import { DecisionDialog } from './Approvals';
import { AccessDetails, RevokeDialog } from './MyAccess';
import styles from './Overview.module.css';

/** Below this share of the granted time the ring turns red. */
const URGENT_FRACTION = 0.15;

function sessionFraction(entry: AccessEntry, now: number): number {
  if (!entry.sessionExpiresAt) return 0;
  const end = new Date(entry.sessionExpiresAt).getTime();
  const total = parseDuration(entry.duration) ?? end - new Date(entry.sessionCreatedAt ?? entry.createdAt).getTime();
  return total > 0 ? (end - now) / total : 0;
}

function minutesLeft(until: string, now: number): number {
  return Math.max(0, Math.ceil((new Date(until).getTime() - now) / 60_000));
}

export function Overview() {
  const { me, access, approvals, navigate } = useAppData();
  const now = useNow();
  const [detail, setDetail] = useState<AccessEntry>();
  const [revoking, setRevoking] = useState<AccessEntry>();
  const [deciding, setDeciding] = useState<{ entry: AccessEntry; decision: Decision }>();

  const { active, open } = useMemo(() => {
    const entries = access.data ?? [];
    return {
      active: entries
        .filter((e) => statusOf(e).group === 'active')
        .sort((a, b) => (a.sessionExpiresAt ?? '').localeCompare(b.sessionExpiresAt ?? '')),
      open: entries.filter((e) => statusOf(e).group === 'open'),
    };
  }, [access.data]);
  const waiting = approvals.data ?? [];
  const firstName = (me.displayName || me.username).split(/[\s@]/)[0];

  const primary = active[0];
  const pendingPrimary = !primary ? open[0] : undefined;
  // The hero already shows the first open request; list only the others.
  const otherOpen = open.filter((e) => e !== pendingPrimary);

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <p className={styles.eyebrow}>Lagebild</p>
        <h1 tabIndex={-1} className={styles.title}>
          Hallo {firstName}.
        </h1>
      </header>

      <section className={styles.hero} aria-label="Dein Zugriff">
        {primary ? (
          <ActiveHero
            entry={primary}
            now={now}
            onDetails={() => setDetail(primary)}
            onRevoke={() => setRevoking(primary)}
          />
        ) : pendingPrimary ? (
          <PendingHero entry={pendingPrimary} now={now} onDetails={() => setDetail(pendingPrimary)} />
        ) : (
          <IdleHero onRequest={() => navigate('request')} />
        )}
      </section>

      {active.length > 1 && (
        <section aria-labelledby="more-active">
          <h2 id="more-active" className={styles.sectionTitle}>
            Weitere aktive Zugriffe
          </h2>
          <ul className={styles.list}>
            {active.slice(1).map((e) => (
              <li key={objectKey(e)}>
                <MiniRow entry={e} now={now} onOpen={() => setDetail(e)} />
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className={styles.columns}>
        <section aria-labelledby="waiting-title" className={styles.panel}>
          <div className={styles.panelHead}>
            <h2 id="waiting-title" className={styles.sectionTitle}>
              Wartet auf dich
            </h2>
            {waiting.length > 0 && <span className={styles.liveCount}>{waiting.length}</span>}
          </div>
          {waiting.length === 0 ? (
            <p className={styles.quiet}>Keine Anträge warten auf deine Freigabe.</p>
          ) : (
            <ul className={styles.list}>
              {waiting.slice(0, 4).map((e) => (
                <li key={objectKey(e)} className={styles.approval}>
                  <span className={styles.pulseDot} aria-hidden="true" />
                  <div className={styles.approvalMain}>
                    <p className={styles.approvalWho}>{e.requester}</p>
                    <p className={styles.meta}>
                      {e.accessProfile} · {formatGoDuration(e.duration)} ·{' '}
                      {e.expiresAt ? (
                        <>
                          verfällt in <span className="tabular">{formatRemaining(new Date(e.expiresAt).getTime() - now)}</span>
                        </>
                      ) : (
                        formatRelative(e.createdAt, now)
                      )}
                    </p>
                  </div>
                  <Button size="sm" variant="primary" onPress={() => setDeciding({ entry: e, decision: 'Approved' })}>
                    Prüfen
                    <Icon name="arrowRight" size={14} />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          {waiting.length > 4 && (
            <Button variant="ghost" size="sm" onPress={() => navigate('approvals')}>
              Alle {waiting.length} Freigaben ansehen
            </Button>
          )}
        </section>

        <section aria-labelledby="open-title" className={styles.panel}>
          <div className={styles.panelHead}>
            <h2 id="open-title" className={styles.sectionTitle}>
              Deine offenen Anträge
            </h2>
          </div>
          {otherOpen.length === 0 ? (
            <p className={styles.quiet}>{pendingPrimary ? 'Keine weiteren offenen Anträge.' : 'Keine offenen Anträge.'}</p>
          ) : (
            <ul className={styles.list}>
              {otherOpen.map((e) => (
                <li key={objectKey(e)}>
                  <MiniRow entry={e} now={now} onOpen={() => setDetail(e)} />
                </li>
              ))}
            </ul>
          )}
          <Button variant="ghost" size="sm" onPress={() => navigate('access')}>
            Alle Zugriffe ansehen
          </Button>
        </section>
      </div>

      {detail && (
        <AccessDetails
          entry={access.data?.find((e) => objectKey(e) === objectKey(detail)) ?? detail}
          now={now}
          onClose={() => setDetail(undefined)}
          onRevoke={() => {
            setRevoking(detail);
            setDetail(undefined);
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
      {deciding && (
        <DecisionDialog
          entry={deciding.entry}
          decision={deciding.decision}
          onClose={() => setDeciding(undefined)}
          onDone={() => {
            setDeciding(undefined);
            void approvals.reload();
          }}
        />
      )}
    </div>
  );
}

function ActiveHero({ entry, now, onDetails, onRevoke }: { entry: AccessEntry; now: number; onDetails: () => void; onRevoke: () => void }) {
  const until = entry.sessionExpiresAt ?? '';
  const remaining = new Date(until).getTime() - now;
  const fraction = sessionFraction(entry, now);
  const urgent = fraction < URGENT_FRACTION;
  const revocable = entry.canRevoke && Boolean(entry.sessionName);

  return (
    <div className={`${styles.heroCard} ${urgent ? styles.heroUrgent : styles.heroActive}`}>
      <Ring
        tone={urgent ? 'urgent' : 'active'}
        fraction={fraction}
        label={`Zugriff aktiv, noch ${minutesLeft(until, now)} Minuten, endet um ${formatTime(until)}`}
      >
        <span className={styles.ringValue}>{formatRemaining(remaining)}</span>
        <span className={styles.ringLabel}>verbleibend</span>
      </Ring>
      <div className={styles.heroBody}>
        <p className={`${styles.heroEyebrow} ${urgent ? styles.eyebrowUrgent : styles.eyebrowActive}`}>
          <span className={styles.liveDot} aria-hidden="true" />
          {urgent ? 'Läuft gleich ab' : 'Aktiver Zugriff'}
        </p>
        <h2 className={styles.heroTitle}>{entry.accessProfile}</h2>
        <dl className={styles.heroFacts}>
          <div>
            <dt>Namespace</dt>
            <dd className="mono">{entry.targetNamespace || '–'}</dd>
          </div>
          <div>
            <dt>Endet um</dt>
            <dd className="tabular">{formatTime(until)}</dd>
          </div>
          {entry.approver && (
            <div>
              <dt>Freigegeben von</dt>
              <dd>{entry.approver}</dd>
            </div>
          )}
        </dl>
        <div className={styles.heroActions}>
          {revocable && (
            <Button variant="danger" onPress={onRevoke}>
              Zugriff beenden
            </Button>
          )}
          <Button onPress={onDetails}>Details</Button>
        </div>
      </div>
    </div>
  );
}

function PendingHero({ entry, now, onDetails }: { entry: AccessEntry; now: number; onDetails: () => void }) {
  const status = statusOf(entry);
  const deadline = entry.kind === 'Request' && !entry.sessionPhase ? entry.expiresAt : undefined;
  return (
    <div className={`${styles.heroCard} ${styles.heroPending}`}>
      <Ring tone="pending" indeterminate label={`${status.label}: ${entry.accessProfile}`}>
        {deadline ? (
          <>
            <span className={styles.ringValue}>{formatRemaining(new Date(deadline).getTime() - now)}</span>
            <span className={styles.ringLabel}>bis zum Verfall</span>
          </>
        ) : (
          <span className={styles.ringLabel}>wird bereitgestellt</span>
        )}
      </Ring>
      <div className={styles.heroBody}>
        <p className={`${styles.heroEyebrow} ${styles.eyebrowPending}`}>
          <span className={styles.liveDot} aria-hidden="true" />
          {status.label}
        </p>
        <h2 className={styles.heroTitle}>{entry.accessProfile}</h2>
        <p className={styles.heroText}>{status.description}</p>
        <dl className={styles.heroFacts}>
          <div>
            <dt>Namespace</dt>
            <dd className="mono">{entry.targetNamespace || '–'}</dd>
          </div>
          <div>
            <dt>Dauer</dt>
            <dd>{formatGoDuration(entry.duration)}</dd>
          </div>
          <div>
            <dt>Gestellt</dt>
            <dd>{formatRelative(entry.createdAt, now)}</dd>
          </div>
        </dl>
        <div className={styles.heroActions}>
          <Button onPress={onDetails}>Details</Button>
        </div>
      </div>
    </div>
  );
}

function IdleHero({ onRequest }: { onRequest: () => void }) {
  return (
    <div className={`${styles.heroCard} ${styles.heroIdle}`}>
      <div className={styles.idleMark} aria-hidden="true">
        <BrandMark size={96} />
      </div>
      <div className={styles.heroBody}>
        <p className={`${styles.heroEyebrow} ${styles.eyebrowIdle}`}>Zero Standing Privileges</p>
        <h2 className={styles.heroTitle}>Kein aktiver Zugriff</h2>
        <p className={styles.heroText}>
          Du hast gerade keine erhöhten Rechte. Im Incident beantragst du hier zeitlich begrenzten, auditierten Zugriff
          auf genau einen Namespace.
        </p>
        <div className={styles.heroActions}>
          <Button variant="primary" onPress={onRequest} className={styles.cta}>
            <Icon name="bolt" />
            Zugriff anfordern
          </Button>
        </div>
      </div>
    </div>
  );
}

function MiniRow({ entry, now, onOpen }: { entry: AccessEntry; now: number; onOpen: () => void }) {
  const status = statusOf(entry);
  return (
    <div className={styles.mini}>
      <div className={styles.miniMain}>
        <p className={styles.miniTitle}>{entry.accessProfile}</p>
        <p className={styles.meta}>
          <span className="mono">{entry.targetNamespace || '–'}</span> · {formatRelative(entry.createdAt, now)}
        </p>
      </div>
      <StatusBadge tone={status.tone} label={status.label} />
      <Button size="sm" variant="ghost" onPress={onOpen} aria-label={`Details zu ${entry.name}`}>
        <Icon name="arrowRight" size={14} />
      </Button>
    </div>
  );
}
