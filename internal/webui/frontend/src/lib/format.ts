const UNIT_MS: Record<string, number> = {
  ns: 1e-6,
  us: 1e-3,
  'µs': 1e-3,
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
};

const DURATION_PATTERN = /^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$/;
const DURATION_PART = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;

/** parseDuration parses a Go duration ("1h30m") as accepted by the CRDs, in milliseconds. */
export function parseDuration(value: string): number | null {
  const input = value.trim();
  if (!DURATION_PATTERN.test(input)) return null;
  let total = 0;
  for (const [, amount, unit] of input.matchAll(DURATION_PART)) {
    total += Number(amount) * (UNIT_MS[unit as string] ?? 0);
  }
  return total;
}

/** formatDuration renders a duration for people, e.g. "1 Std. 30 Min.". */
export function formatDuration(ms: number): string {
  const totalMinutes = Math.round(ms / 60_000);
  if (totalMinutes < 1) return `${Math.round(ms / 1000)} Sek.`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) return `${minutes} Min.`;
  return minutes === 0 ? `${hours} Std.` : `${hours} Std. ${minutes} Min.`;
}

/** formatGoDuration renders a Go duration string for people, falling back to the raw value. */
export function formatGoDuration(value: string): string {
  const ms = parseDuration(value);
  return ms === null ? value : formatDuration(ms);
}

const dateTimeFormat = new Intl.DateTimeFormat('de-DE', {
  day: '2-digit',
  month: '2-digit',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZoneName: 'short',
});

const timeFormat = new Intl.DateTimeFormat('de-DE', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZoneName: 'short',
});

/** formatDateTime renders an absolute timestamp including its time zone. */
export function formatDateTime(iso: string | undefined): string {
  if (!iso) return '–';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '–' : dateTimeFormat.format(date);
}

export function formatTime(iso: string | undefined): string {
  if (!iso) return '–';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '–' : timeFormat.format(date);
}

/** formatRemaining renders the time left as "mm:ss" or "h:mm:ss". */
export function formatRemaining(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const mm = String(minutes).padStart(2, '0');
  const ss = String(seconds).padStart(2, '0');
  return hours > 0 ? `${hours}:${mm}:${ss}` : `${mm}:${ss}`;
}

const relativeFormat = new Intl.RelativeTimeFormat('de-DE', { numeric: 'auto' });

/** formatRelative renders "vor 5 Minuten" style text relative to now. */
export function formatRelative(iso: string | undefined, now: number): string {
  if (!iso) return '–';
  const diff = new Date(iso).getTime() - now;
  if (Number.isNaN(diff)) return '–';
  const abs = Math.abs(diff);
  if (abs < 60_000) return relativeFormat.format(Math.round(diff / 1000), 'second');
  if (abs < 3_600_000) return relativeFormat.format(Math.round(diff / 60_000), 'minute');
  if (abs < 86_400_000) return relativeFormat.format(Math.round(diff / 3_600_000), 'hour');
  return relativeFormat.format(Math.round(diff / 86_400_000), 'day');
}
