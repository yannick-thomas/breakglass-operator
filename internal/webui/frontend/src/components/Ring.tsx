import { useId, type ReactNode } from 'react';
import styles from './Ring.module.css';

const SIZE = 200;
const RADIUS = 84;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const TICKS = Array.from({ length: 60 }, (_, i) => i);

export type RingTone = 'active' | 'urgent' | 'pending' | 'idle';

export interface RingProps {
  /** 0..1 of the arc to fill; ignored while indeterminate. */
  fraction?: number;
  indeterminate?: boolean;
  tone: RingTone;
  /** Accessible summary; the ring itself is presentational. */
  label: string;
  children?: ReactNode;
}

/**
 * Ring is an instrument-style gauge: a 60-tick dial with a glowing progress
 * arc. It is exposed to assistive technology as a single image with a text
 * summary, so the per-second animation never interrupts a screen reader.
 */
export function Ring({ fraction = 0, indeterminate, tone, label, children }: RingProps) {
  const id = useId();
  const clamped = Math.min(1, Math.max(0, fraction));
  const offset = CIRCUMFERENCE * (1 - (indeterminate ? 0.22 : clamped));

  return (
    <div className={`${styles.ring} ${styles[tone]}`} role="img" aria-label={label}>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className={styles.svg} aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id={`${id}-arc`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" className={styles.stopStart} />
            <stop offset="1" className={styles.stopEnd} />
          </linearGradient>
        </defs>
        <g className={styles.ticks}>
          {TICKS.map((i) => (
            <line
              key={i}
              x1={SIZE / 2}
              y1={i % 5 === 0 ? 3 : 6}
              x2={SIZE / 2}
              y2={10}
              transform={`rotate(${i * 6} ${SIZE / 2} ${SIZE / 2})`}
              className={i % 5 === 0 ? styles.tickMajor : undefined}
            />
          ))}
        </g>
        <circle cx={SIZE / 2} cy={SIZE / 2} r={RADIUS} className={styles.track} />
        <g className={indeterminate ? styles.spin : undefined}>
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            className={styles.arc}
            stroke={`url(#${id}-arc)`}
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}
          />
        </g>
      </svg>
      <div className={styles.center}>{children}</div>
    </div>
  );
}
