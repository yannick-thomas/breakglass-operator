import { useAppData } from '../AppContext';
import { domId, objectKey } from '../api/objectKey';
import { Button } from '../components/Button';
import { EmptyState, Loading, Notice, StatusBadge } from '../components/Feedback';
import { formatGoDuration } from '../lib/format';
import { PageHeader } from './PageHeader';
import page from './page.module.css';
import styles from './Profiles.module.css';

export function Profiles() {
  const { profiles, navigate } = useAppData();
  const items = profiles.data ?? [];

  return (
    <div className={page.page}>
      <PageHeader
        title="Profile"
        description="Die Profile, die du verwenden darfst. Sie werden vom Plattform-Team versioniert gepflegt und lassen sich hier nicht ändern."
      />

      {profiles.error && (
        <Notice tone="danger" title="Profile konnten nicht geladen werden.">
          {profiles.error.message}
        </Notice>
      )}

      {profiles.loading ? (
        <Loading label="Profile werden geladen…" />
      ) : items.length === 0 ? (
        <div className={page.card}>
          <EmptyState icon="catalog" title="Für deine Identität ist kein Profil freigegeben." />
        </div>
      ) : (
        <ul className={styles.grid}>
          {items.map((p) => (
            <li key={objectKey(p)} className={page.card}>
              <article className={styles.profile} aria-labelledby={domId('profile', p)}>
                <div className={styles.head}>
                  <h2 id={domId('profile', p)} className={styles.name}>
                    {p.name}
                  </h2>
                  {p.isReady ? (
                    <StatusBadge
                      tone={p.deliveryMode === 'ApprovalRequired' ? 'warning' : 'info'}
                      label={p.deliveryMode === 'ApprovalRequired' ? 'Freigabe nötig' : 'Self-Service'}
                    />
                  ) : (
                    <StatusBadge tone="danger" label="Nicht einsatzbereit" />
                  )}
                </div>
                <p className={page.muted}>{p.description}</p>
                <dl className={page.facts}>
                  <dt>Namespace</dt>
                  <dd className={page.mono}>{p.targetNamespace}</dd>
                  <dt>Rolle</dt>
                  <dd className={page.mono}>{p.roleRef}</dd>
                  <dt>Höchstdauer</dt>
                  <dd>{formatGoDuration(p.maxDuration)}</dd>
                </dl>
                {!p.isReady && (
                  <Notice tone="danger">
                    Das Profil ist falsch konfiguriert und kann im Moment nicht verwendet werden. Informiere das
                    Plattform-Team vor dem nächsten Incident.
                  </Notice>
                )}
                {p.isReady && (
                  <div className={styles.footer}>
                    <Button size="sm" onPress={() => navigate('request')}>
                      Zugriff anfordern
                    </Button>
                  </div>
                )}
              </article>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
