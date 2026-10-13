import type { ReactNode } from 'react';
import { Dialog, Heading, Modal, ModalOverlay } from 'react-aria-components';
import styles from './Dialog.module.css';

export interface AppDialogProps {
  title: string;
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  children: ReactNode;
  footer?: ReactNode;
  /** alertdialog for confirmations of consequential actions. */
  role?: 'dialog' | 'alertdialog';
  /** A consequential confirmation must not close on an outside click. */
  isDismissable?: boolean;
  size?: 'md' | 'lg';
}

/**
 * AppDialog is a modal dialog with focus containment, focus restore on close
 * and Escape handling, all provided by React Aria.
 */
export function AppDialog({
  title,
  isOpen,
  onOpenChange,
  children,
  footer,
  role = 'dialog',
  isDismissable = true,
  size = 'md',
}: AppDialogProps) {
  return (
    <ModalOverlay isOpen={isOpen} onOpenChange={onOpenChange} isDismissable={isDismissable} className={styles.overlay}>
      <Modal className={`${styles.modal} ${styles[size]}`}>
        <Dialog role={role} className={styles.dialog}>
          <Heading slot="title" className={styles.title}>
            {title}
          </Heading>
          <div className={styles.body}>{children}</div>
          {footer && <div className={styles.footer}>{footer}</div>}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}
