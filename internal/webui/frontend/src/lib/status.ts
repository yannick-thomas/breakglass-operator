import type { AccessEntry } from '../api/types';

export type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral';
export type StatusGroup = 'active' | 'open' | 'history';

export interface StatusInfo {
  label: string;
  tone: Tone;
  group: StatusGroup;
  description: string;
}

/**
 * statusOf derives the one status shown for an entry: once a session exists
 * its phase is authoritative, before that the request phase. Labels describe
 * what the person can do, never controller internals.
 */
export function statusOf(entry: AccessEntry): StatusInfo {
  const phase = entry.sessionPhase || entry.phase || 'Pending';
  const isSession = Boolean(entry.sessionPhase);

  switch (phase) {
    case 'Active':
      return {
        label: 'Aktiv',
        tone: 'success',
        group: 'active',
        description: 'Der Zugriff ist aktiv und endet automatisch zum angezeigten Zeitpunkt.',
      };
    case 'Pending':
      return isSession
        ? {
            label: 'Wird bereitgestellt',
            tone: 'info',
            group: 'open',
            description: 'Der Controller richtet die Berechtigung ein.',
          }
        : {
            label: 'Wartet auf Freigabe',
            tone: 'warning',
            group: 'open',
            description: 'Ein Antrag ist noch kein Zugriff. Er wird erst nach unabhängiger Freigabe aktiv.',
          };
    case 'Approved':
    case 'Provisioning':
    case 'SessionCreated':
      return {
        label: 'Freigegeben',
        tone: 'info',
        group: 'open',
        description: 'Der Antrag wurde freigegeben; der Zugriff wird bereitgestellt.',
      };
    case 'Denied':
      return {
        label: 'Abgelehnt',
        tone: 'danger',
        group: 'history',
        description: 'Der Antrag wurde abgelehnt. Es wurde kein Zugriff gewährt.',
      };
    case 'Expired':
      return isSession
        ? {
            label: 'Abgelaufen',
            tone: 'neutral',
            group: 'history',
            description: 'Die Laufzeit ist abgelaufen; die Berechtigung wurde entfernt.',
          }
        : {
            label: 'Verfallen',
            tone: 'neutral',
            group: 'history',
            description:
              'Es wurde nicht rechtzeitig entschieden. Stelle bei Bedarf einen neuen Antrag mit aktuellem Incident-Kontext.',
          };
    case 'Revoked':
      return {
        label: 'Beendet',
        tone: 'neutral',
        group: 'history',
        description: 'Der Zugriff wurde vorzeitig beendet; die Berechtigung wurde entfernt.',
      };
    case 'Suspended':
      return {
        label: 'Entzogen',
        tone: 'danger',
        group: 'history',
        description:
          'Der Zugriff wurde entfernt, weil seine Integrität nicht nachweisbar war. Prüfe Runbook und Audit-Log. Eine automatische Reaktivierung gibt es nicht.',
      };
    case 'Failed':
      return {
        label: 'Fehlgeschlagen',
        tone: 'danger',
        group: 'history',
        description: 'Der Zugriff konnte nicht bereitgestellt werden. Wende dich an das Plattform-Team.',
      };
    default:
      return { label: phase, tone: 'neutral', group: 'history', description: '' };
  }
}
