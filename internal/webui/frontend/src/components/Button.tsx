import { Button as AriaButton, type ButtonProps as AriaButtonProps } from 'react-aria-components';
import styles from './Button.module.css';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';

export interface ButtonProps extends Omit<AriaButtonProps, 'className'> {
  variant?: ButtonVariant;
  size?: 'sm' | 'md';
  className?: string;
}

export function Button({ variant = 'secondary', size = 'md', className, children, ...props }: ButtonProps) {
  return (
    <AriaButton
      {...props}
      className={[styles.button, styles[variant], styles[size], className].filter(Boolean).join(' ')}
    >
      {children}
    </AriaButton>
  );
}
