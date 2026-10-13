import type { AccessEntry } from '../api/types';
import { formatDateTime } from '../lib/format';
import { statusOf } from '../lib/status';
import styles from './Timeline.module.css';

interface Step {
  title: string;
  time?: string;
  detail?: string;
  state: 'done' | 'current' | 'failed';
}

function stepsFor(entry: AccessEntry): Step[] {
  const isRequest = entry.kind === 'Request';
  const steps: Step[] = [
    {
      title: isRequest ? 'Antrag eingereicht' : 'Self-Service-Zugriff angelegt',
      time: entry.createdAt,
      detail: `von ${entry.requester}`,
      state: 'done',
    },
  ];

  if (isRequest) {
    if (entry.approvalDecision) {
      const approved = entry.approvalDecision === 'Approved';
      steps.push({
        title: approved ? 'Freigegeben' : 'Abgelehnt',
        time: entry.approvalCreatedAt,
        detail: `von ${entry.approver ?? 'unbekannt'}${entry.approvalComment ? `: „${entry.approvalComment}“` : ''}`,
        state: approved ? 'done' : 'failed',
      });
    } else if (entry.phase === 'Expired') {
      steps.push({ title: 'Ohne Entscheidung verfallen', time: entry.expiresAt, state: 'failed' });
    } else if (!entry.sessionPhase) {
      steps.push({
        title: 'Wartet auf Freigabe',
        detail: entry.expiresAt ? `verfällt am ${formatDateTime(entry.expiresAt)}` : undefined,
        state: 'current',
      });
    }
  }

  if (entry.sessionPhase) {
    const status = statusOf(entry);
    const ended = status.group === 'history';
    steps.push({
      title: 'Zugriff bereitgestellt',
      time: entry.sessionCreatedAt,
      detail: `Namespace ${entry.targetNamespace || '–'}`,
      state: ended || entry.sessionPhase === 'Active' ? 'done' : 'current',
    });
    if (entry.sessionPhase === 'Active') {
      steps.push({
        title: 'Aktiv',
        detail: entry.sessionExpiresAt ? `endet am ${formatDateTime(entry.sessionExpiresAt)}` : undefined,
        state: 'current',
      });
    } else if (ended) {
      steps.push({
        title: status.label,
        detail: status.description,
        state: status.tone === 'danger' ? 'failed' : 'done',
      });
    }
  }
  return steps;
}

export function Timeline({ entry }: { entry: AccessEntry }) {
  return (
    <ol className={styles.timeline} aria-label="Verlauf">
      {stepsFor(entry).map((step, i) => (
        <li key={i} className={styles.step} data-state={step.state}>
          <span className={styles.marker} aria-hidden="true" />
          <div>
            <p className={styles.title}>
              {step.title}
              {step.state === 'current' && <span className="visually-hidden"> (aktueller Schritt)</span>}
            </p>
            {step.time && (
              <p className={styles.meta}>
                <time dateTime={step.time}>{formatDateTime(step.time)}</time>
              </p>
            )}
            {step.detail && <p className={styles.meta}>{step.detail}</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}
