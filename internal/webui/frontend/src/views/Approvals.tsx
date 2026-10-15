import { useState } from 'react';
import { useAppData } from '../AppContext';
import { ApiError } from '../api/client';
import { objectKey } from '../api/objectKey';
import type { AccessEntry, Decision } from '../api/types';
import { Button } from '../components/Button';
import { Countdown } from '../components/Countdown';
import { AppDialog } from '../components/Dialog';
import { EmptyState, Loading, Notice } from '../components/Feedback';
import { CheckboxField, TextAreaField } from '../components/Fields';
import { Icon } from '../components/Icon';
import { useNotify } from '../components/Toaster';
import { useNow } from '../hooks/useNow';
import { formatGoDuration, formatRelative } from '../lib/format';
import { PageHeader } from './PageHeader';
import page from './page.module.css';
import styles from './Approvals.module.css';

export const COMMENT_MAX = 1024;

export function Approvals() {
  const { approvals } = useAppData();
  const now = useNow();
  const [deciding, setDeciding] = useState<{ entry: AccessEntry; decision: Decision }>();
  const items = approvals.data ?? [];

  return (
    <div className={page.page}>
      <PageHeader
        title="Freigaben"
        description="Offene Anträge anderer Personen für Profile, die du freigeben darfst. Eigene Anträge erscheinen hier nie."
        actions={
          <Button variant="ghost" size="sm" onPress={() => void approvals.reload()}>
            <Icon name="refresh" />
            Aktualisieren
          </Button>
        }
      />

      {approvals.error && (
        <Notice tone="danger" title="Freigaben konnten nicht geladen werden.">
          {approvals.error.message}
        </Notice>
      )}

      {approvals.loading && !approvals.data ? (
        <Loading label="Freigaben werden geladen…" />
      ) : items.length === 0 ? (
        <div className={page.card}>
          <EmptyState icon="shield" title="Keine offenen Anträge.">
            Hier erscheinen Anträge, für die du freigabeberechtigt bist.
          </EmptyState>
        </div>
      ) : (
        <ul className={page.list}>
          {items.map((entry) => (
            <li key={objectKey(entry)}>
              <article className={page.card} aria-labelledby={`approval-${entry.name}`}>
                <div className={`${page.cardBody} ${styles.body}`}>
                  <div className={styles.head}>
                    <div>
                      <h2 id={`approval-${entry.name}`} className={styles.requester}>
                        {entry.requester}
                      </h2>
                      <p className={page.sectionHint}>
                        beantragt <strong>{entry.accessProfile}</strong> · {formatRelative(entry.createdAt, now)}
                      </p>
                    </div>
                    {entry.expiresAt && (
                      <p className={styles.expiry}>
                        <Icon name="clock" />
                        <span>
                          Verfällt in <Countdown until={entry.expiresAt} now={now} />
                        </span>
                      </p>
                    )}
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
                    <div>
                      <dt>Referenz</dt>
                      <dd className={page.mono}>{entry.name}</dd>
                    </div>
                  </dl>
                  <p className={page.reason}>{entry.reason}</p>
                </div>
                <div className={page.actionsBar}>
                  <Button onPress={() => setDeciding({ entry, decision: 'Denied' })}>Ablehnen</Button>
                  <Button variant="primary" onPress={() => setDeciding({ entry, decision: 'Approved' })}>
                    Prüfen und freigeben
                  </Button>
                </div>
              </article>
            </li>
          ))}
        </ul>
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

export function DecisionDialog({ entry, decision, onClose, onDone }: { entry: AccessEntry; decision: Decision; onClose: () => void; onDone: () => void }) {
  const { api } = useAppData();
  const notify = useNotify();
  const [notRequester, setNotRequester] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const [comment, setComment] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  const approve = decision === 'Approved';
  const canSubmit = !pending && (!approve || (notRequester && reviewed)) && comment.length <= COMMENT_MAX;

  async function submit() {
    setPending(true);
    setError(undefined);
    try {
      await api.decide(entry.namespace, entry.name, decision, comment.trim());
      notify(approve ? `Antrag ${entry.name} freigegeben.` : `Antrag ${entry.name} abgelehnt.`, 'success');
      onDone();
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 409)) {
        // Someone else decided, or the request expired meanwhile.
        notify(err.message, 'danger');
        onDone();
        return;
      }
      setError(err instanceof ApiError ? err.message : String(err));
      setPending(false);
    }
  }

  return (
    <AppDialog
      title={approve ? 'Zugriff freigeben' : 'Antrag ablehnen'}
      role="alertdialog"
      isDismissable={false}
      isOpen
      onOpenChange={(open) => !open && !pending && onClose()}
      footer={
        <>
          <Button onPress={onClose} isDisabled={pending}>
            Abbrechen
          </Button>
          <Button variant={approve ? 'primary' : 'danger'} onPress={submit} isDisabled={!canSubmit} isPending={pending}>
            {pending ? 'Wird gespeichert…' : approve ? 'Verbindlich freigeben' : 'Ablehnen'}
          </Button>
        </>
      }
    >
      <dl className={page.facts}>
        <dt>Antragsteller</dt>
        <dd>{entry.requester}</dd>
        <dt>Profil</dt>
        <dd>{entry.accessProfile}</dd>
        <dt>Namespace</dt>
        <dd className={page.mono}>{entry.targetNamespace || '–'}</dd>
        <dt>Dauer</dt>
        <dd>{formatGoDuration(entry.duration)}</dd>
        <dt>Begründung</dt>
        <dd className={page.reason}>{entry.reason}</dd>
      </dl>

      {approve && (
        <fieldset className={styles.checks}>
          <legend className={page.sectionTitle}>Bestätigung</legend>
          <CheckboxField isSelected={notRequester} onChange={setNotRequester}>
            Ich bin nicht die antragstellende Person.
          </CheckboxField>
          <CheckboxField isSelected={reviewed} onChange={setReviewed}>
            Ich habe Profil, Dauer und Begründung geprüft; der Zugriff ist für diesen Incident erforderlich.
          </CheckboxField>
        </fieldset>
      )}

      <TextAreaField
        label="Kommentar"
        value={comment}
        onChange={setComment}
        rows={2}
        maxLength={COMMENT_MAX}
        description="Optional, wird mit der Entscheidung gespeichert. Keine Geheimnisse eingeben."
      />

      {error && (
        <Notice tone="danger" title="Die Entscheidung wurde nicht gespeichert." urgent>
          {error}
        </Notice>
      )}
    </AppDialog>
  );
}
