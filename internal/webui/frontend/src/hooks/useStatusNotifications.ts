import { useEffect, useRef } from 'react';
import type { AccessEntry } from '../api/types';
import { useNotify } from '../components/Toaster';
import { statusOf } from '../lib/status';

function statusKey(entry: AccessEntry): string {
  return entry.sessionPhase || entry.phase || 'Pending';
}

/**
 * useStatusNotifications announces changes that happen elsewhere, for example
 * an approval by another person or the controller activating access. Changes
 * caused by this page (a new request) are not announced twice: only entries
 * already known from an earlier poll are compared.
 */
export function useStatusNotifications(entries: AccessEntry[] | undefined): void {
  const notify = useNotify();
  const previous = useRef<Map<string, string> | null>(null);

  useEffect(() => {
    if (!entries) return;
    const current = new Map(entries.map((e) => [e.name, statusKey(e)]));
    const before = previous.current;
    previous.current = current;
    if (!before) return;

    for (const entry of entries) {
      const was = before.get(entry.name);
      const now = current.get(entry.name);
      if (!was || was === now) continue;

      const status = statusOf(entry);
      switch (now) {
        case 'Active':
          notify(`Zugriff ${entry.accessProfile} ist jetzt aktiv.`, 'success');
          break;
        case 'Approved':
        case 'Provisioning':
        case 'SessionCreated':
          notify(`Antrag ${entry.name} wurde freigegeben.`, 'success');
          break;
        case 'Denied':
        case 'Suspended':
        case 'Failed':
          notify(`${entry.accessProfile}: ${status.label}. ${status.description}`, 'danger');
          break;
        case 'Expired':
        case 'Revoked':
          notify(`${entry.accessProfile}: ${status.label}.`, 'info');
          break;
      }
    }
  }, [entries, notify]);
}
