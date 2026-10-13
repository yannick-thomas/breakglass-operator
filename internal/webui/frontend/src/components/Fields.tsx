import type { ReactNode } from 'react';
import {
  Checkbox,
  FieldError,
  Input,
  Label,
  Text,
  TextArea,
  TextField,
} from 'react-aria-components';
import { Icon } from './Icon';
import styles from './Fields.module.css';

interface BaseFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  description?: ReactNode;
  /** Shown, and announced, only when set. */
  error?: string;
  isRequired?: boolean;
  maxLength?: number;
  name?: string;
}

export function TextInputField({ label, value, onChange, description, error, isRequired, maxLength, name, placeholder }: BaseFieldProps & { placeholder?: string }) {
  return (
    <TextField
      className={styles.field}
      value={value}
      onChange={onChange}
      isRequired={isRequired}
      isInvalid={Boolean(error)}
      validationBehavior="aria"
      maxLength={maxLength}
      name={name}
    >
      <Label className={styles.label}>
        {label}
        {isRequired && <span aria-hidden="true"> *</span>}
      </Label>
      <Input className={styles.input} placeholder={placeholder} />
      {description && (
        <Text slot="description" className={styles.description}>
          {description}
        </Text>
      )}
      <FieldError className={styles.error}>{error}</FieldError>
    </TextField>
  );
}

export function TextAreaField({ label, value, onChange, description, error, isRequired, maxLength, name, rows = 4 }: BaseFieldProps & { rows?: number }) {
  return (
    <TextField
      className={styles.field}
      value={value}
      onChange={onChange}
      isRequired={isRequired}
      isInvalid={Boolean(error)}
      validationBehavior="aria"
      maxLength={maxLength}
      name={name}
    >
      <Label className={styles.label}>
        {label}
        {isRequired && <span aria-hidden="true"> *</span>}
      </Label>
      <TextArea className={`${styles.input} ${styles.textarea}`} rows={rows} />
      {description && (
        <Text slot="description" className={styles.description}>
          {description}
        </Text>
      )}
      <FieldError className={styles.error}>{error}</FieldError>
    </TextField>
  );
}

export function CheckboxField({ isSelected, onChange, children }: { isSelected: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return (
    <Checkbox className={styles.checkbox} isSelected={isSelected} onChange={onChange}>
      {({ isSelected: selected }) => (
        <>
          <span className={styles.checkboxBox} data-checked={selected || undefined}>
            {selected && <Icon name="check" size={13} />}
          </span>
          <span>{children}</span>
        </>
      )}
    </Checkbox>
  );
}

export const fieldStyles = styles;
