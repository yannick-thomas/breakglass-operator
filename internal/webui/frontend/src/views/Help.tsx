import type { AccessEntry } from '../api/types';
import { StatusBadge } from '../components/Feedback';
import { statusOf } from '../lib/status';
import { PageHeader } from './PageHeader';
import page from './page.module.css';
import styles from './Help.module.css';

const STEPS = [
  {
    title: 'Profil wählen',
    text: 'Das Plattform-Team legt Rolle, Namespace und Höchstdauer fest. Du wählst nur Profil, Dauer und Begründung.',
  },
  {
    title: 'Freigabe abwarten',
    text: 'Profile mit Freigabepflicht brauchen eine zweite, berechtigte Person. Eigene Anträge kannst du nicht freigeben.',
  },
  {
    title: 'Arbeiten',
    text: 'Der Zugriff gilt nur im Namespace des Profils und endet automatisch. Beende ihn früher, wenn du fertig bist.',
  },
];

// Representative entries to render the status legend from the same mapping the app uses.
const LEGEND: Pick<AccessEntry, 'phase' | 'sessionPhase'>[] = [
  { phase: 'Pending' },
  { phase: 'Approved' },
  { phase: 'SessionCreated', sessionPhase: 'Active' },
  { phase: 'SessionCreated', sessionPhase: 'Expired' },
  { phase: 'SessionCreated', sessionPhase: 'Revoked' },
  { phase: 'SessionCreated', sessionPhase: 'Suspended' },
  { phase: 'Denied' },
  { phase: 'Expired' },
];

export function Help() {
  return (
    <div className={page.page}>
      <PageHeader title="Hilfe" description="Wie BreakGlass funktioniert und was die Status bedeuten." />

      <section className={page.card} aria-labelledby="help-flow">
        <div className={page.cardBody}>
          <h2 id="help-flow" className={page.sectionTitle}>
            So funktioniert es
          </h2>
          <ol className={styles.steps}>
            {STEPS.map((step, i) => (
              <li key={step.title} className={styles.step}>
                <span className={styles.stepNumber} aria-hidden="true">
                  {i + 1}
                </span>
                <div>
                  <p className={styles.stepTitle}>{step.title}</p>
                  <p className={page.muted}>{step.text}</p>
                </div>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className={page.card} aria-labelledby="help-status">
        <div className={page.cardBody}>
          <h2 id="help-status" className={page.sectionTitle}>
            Status
          </h2>
          <dl className={styles.legend}>
            {LEGEND.map((entry) => {
              const status = statusOf({ ...entry, kind: entry.sessionPhase ? 'Session' : 'Request' } as AccessEntry);
              return (
                <div key={`${entry.phase}-${entry.sessionPhase ?? ''}`} className={styles.legendRow}>
                  <dt>
                    <StatusBadge tone={status.tone} label={status.label} />
                  </dt>
                  <dd className={page.muted}>{status.description}</dd>
                </div>
              );
            })}
          </dl>
        </div>
      </section>

      <section className={page.card} aria-labelledby="help-outage">
        <div className={page.cardBody}>
          <h2 id="help-outage" className={page.sectionTitle}>
            Wenn etwas nicht funktioniert
          </h2>
          <ul className={styles.bullets}>
            <li>
              Kann ein Antrag aus Sicherheitsgründen nicht angenommen werden, gibt es bewusst keinen Umweg. Folge dem
              dokumentierten Notfallverfahren deines Teams.
            </li>
            <li>
              Ist die Oberfläche nicht erreichbar, funktioniert derselbe Ablauf mit <code>kubectl</code>; die
              Berechtigungen sind identisch.
            </li>
            <li>Ein entzogener Zugriff wird nie automatisch wiederhergestellt. Prüfe Runbook und Audit-Log.</li>
          </ul>
        </div>
      </section>

      <section className={page.card} aria-labelledby="help-privacy">
        <div className={page.cardBody}>
          <h2 id="help-privacy" className={page.sectionTitle}>
            Datenschutz und Audit
          </h2>
          <p className={page.muted}>
            Anträge, Freigaben und Widerrufe werden mit deiner Kubernetes-Identität im Audit-Log des Clusters erfasst.
            Du siehst nur deine eigenen Anträge und Anträge, die du freigeben darfst. Gib in Begründungen und Kommentaren
            nie Passwörter, Tokens oder andere Geheimnisse ein.
          </p>
        </div>
      </section>
    </div>
  );
}
