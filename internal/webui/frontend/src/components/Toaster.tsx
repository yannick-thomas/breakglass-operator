import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { Button } from './Button';
import { feedbackStyles as styles, TONE_ICON } from './Feedback';
import { Icon } from './Icon';

type ToastTone = 'success' | 'info' | 'danger';

interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
}

type Notify = (message: string, tone?: ToastTone) => void;

const NotifyContext = createContext<Notify>(() => undefined);

export function useNotify(): Notify {
  return useContext(NotifyContext);
}

/**
 * Toaster shows short confirmations. Both live regions exist from the first
 * render so screen readers announce later messages reliably; errors use an
 * assertive region and stay until dismissed.
 */
export function Toaster({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const notify = useCallback<Notify>(
    (message, tone = 'success') => {
      const id = nextId.current++;
      setToasts((current) => [...current.slice(-3), { id, tone, message }]);
      if (tone !== 'danger') window.setTimeout(() => dismiss(id), 6000);
    },
    [dismiss],
  );

  const render = (list: Toast[]) =>
    list.map((toast) => (
      <div key={toast.id} className={`${styles.toast} ${styles[toast.tone]}`}>
        <Icon name={TONE_ICON[toast.tone]} />
        <span className={styles.toastText}>{toast.message}</span>
        <Button variant="ghost" size="sm" aria-label="Benachrichtigung schließen" onPress={() => dismiss(toast.id)}>
          <Icon name="x" />
        </Button>
      </div>
    ));

  const value = useMemo(() => notify, [notify]);

  return (
    <NotifyContext.Provider value={value}>
      {children}
      <div className={styles.toaster}>
        <div aria-live="polite" role="status">
          {render(toasts.filter((t) => t.tone !== 'danger'))}
        </div>
        <div aria-live="assertive" role="alert">
          {render(toasts.filter((t) => t.tone === 'danger'))}
        </div>
      </div>
    </NotifyContext.Provider>
  );
}
