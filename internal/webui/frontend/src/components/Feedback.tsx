import type { ReactNode } from 'react';
import type { Tone } from '../lib/status';
import { Icon, type IconName } from './Icon';
import styles from './feedback.module.css';

const TONE_ICON: Record<Tone, IconName> = {
  success: 'check',
  warning: 'clock',
  danger: 'alert',
  info: 'info',
  neutral: 'info',
};

export function StatusBadge({ tone, label }: { tone: Tone; label: string }) {
  return (
    <span className={`${styles.badge} ${styles[tone]}`}>
      <Icon name={TONE_ICON[tone]} size={13} className={styles.badgeIcon} />
      {label}
    </span>
  );
}

export interface NoticeProps {
  tone: Tone;
  title?: string;
  children?: ReactNode;
  /** Announce immediately; use for errors caused by the person's last action. */
  urgent?: boolean;
}

export function Notice({ tone, title, children, urgent }: NoticeProps) {
  return (
    <div className={`${styles.notice} ${styles[tone]}`} role={urgent ? 'alert' : undefined}>
      <Icon name={TONE_ICON[tone]} />
      <div className={styles.noticeBody}>
        {title && <div className={styles.noticeTitle}>{title}</div>}
        {children && <div className={styles.noticeText}>{children}</div>}
      </div>
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon: IconName; title: string; children?: ReactNode }) {
  return (
    <div className={styles.empty}>
      <span className={styles.emptyIcon}>
        <Icon name={icon} size={20} />
      </span>
      <p className={styles.emptyTitle}>{title}</p>
      {children && <div>{children}</div>}
    </div>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <p className={styles.loading} role="status">
      {label}
    </p>
  );
}

export { TONE_ICON };
export const feedbackStyles = styles;
