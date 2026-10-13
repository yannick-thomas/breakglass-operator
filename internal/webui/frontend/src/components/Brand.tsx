import { useId } from 'react';
import styles from './Brand.module.css';

/** BrandMark is the BreakGlass logo: a pane of glass cracked from one point of impact. */
export function BrandMark({ size = 32, className }: { size?: number; className?: string }) {
  const id = useId();
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      aria-hidden="true"
      focusable="false"
      className={className}
    >
      <defs>
        <linearGradient id={`${id}-bg`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#ff8a4c" />
          <stop offset="1" stopColor="#e2380f" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="8" fill={`url(#${id}-bg)`} />
      <rect x="6.5" y="6.5" width="19" height="19" rx="3" fill="none" stroke="#fff" strokeOpacity="0.35" strokeWidth="1.2" />
      <g fill="none" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 13.5 25.5 8" />
        <path d="M18 13.5 25.5 19.5" />
        <path d="M18 13.5 14.5 25.5" />
        <path d="M18 13.5 6.5 18" />
        <path d="M18 13.5 11 6.5" />
        <path d="M21.6 16.4 20.4 21.2" strokeOpacity="0.7" />
        <path d="M12.5 15.9 10.6 12.3" strokeOpacity="0.7" />
      </g>
      <circle cx="18" cy="13.5" r="1.9" fill="#fff" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className={styles.wordmark}>
      <span className={styles.break}>Break</span>
      <span>Glass</span>
    </span>
  );
}
