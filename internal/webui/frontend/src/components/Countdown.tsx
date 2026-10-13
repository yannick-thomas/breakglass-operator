import { formatRemaining, formatTime } from '../lib/format';

/**
 * Countdown shows the time left and the absolute end. The absolute time is
 * authoritative; the ticking value is deliberately not a live region, so
 * screen readers are not interrupted every second.
 */
export function Countdown({ until, now }: { until: string; now: number }) {
  const remaining = new Date(until).getTime() - now;
  if (Number.isNaN(remaining)) return null;
  if (remaining <= 0) {
    return <time dateTime={until}>beendet um {formatTime(until)}</time>;
  }
  return (
    <span>
      <span className="mono" aria-hidden="true">
        {formatRemaining(remaining)}
      </span>{' '}
      <span>
        (bis <time dateTime={until}>{formatTime(until)}</time>)
      </span>
    </span>
  );
}
