import type { ReactNode } from 'react';
import styles from './page.module.css';

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className={styles.pageHeader}>
      <div>
        {/* tabIndex lets the shell move focus here after navigation. */}
        <h1 className={styles.pageTitle} tabIndex={-1}>
          {title}
        </h1>
        {description && <p className={styles.pageDescription}>{description}</p>}
      </div>
      {actions && <div className={styles.actions}>{actions}</div>}
    </header>
  );
}
