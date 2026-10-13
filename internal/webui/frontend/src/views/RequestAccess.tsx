import { useMemo, useState } from 'react';
import { FieldError, Label, Radio, RadioGroup, Text } from 'react-aria-components';
import { useAppData } from '../AppContext';
import { ApiError } from '../api/client';
import type { AccessEntry, Profile } from '../api/types';
import { Button } from '../components/Button';
import { EmptyState, Loading, Notice, StatusBadge } from '../components/Feedback';
import { fieldStyles, TextAreaField, TextInputField } from '../components/Fields';
import { Icon } from '../components/Icon';
import { formatGoDuration, parseDuration } from '../lib/format';
import { statusOf } from '../lib/status';
import { PageHeader } from './PageHeader';
import page from './page.module.css';
import styles from './RequestAccess.module.css';

const PRESETS = ['15m', '30m', '1h', '2h', '4h'];
export const REASON_MIN = 5;
export const REASON_MAX = 1024;

type Step = 'form' | 'review' | 'done';

interface FormErrors {
  profile?: string;
  duration?: string;
  reason?: string;
}

export function validate(profile: Profile | undefined, duration: string, reason: string): FormErrors {
  const errors: FormErrors = {};
  if (!profile) errors.profile = 'Wähle ein Profil aus.';

  const ms = parseDuration(duration);
  if (ms === null || ms <= 0) {
    errors.duration = 'Gib eine Dauer wie 30m, 1h oder 1h30m an.';
  } else if (profile) {
    const max = parseDuration(profile.maxDuration);
    if (max !== null && ms > max) {
      errors.duration = `Zu lang: Dieses Profil erlaubt höchstens ${formatGoDuration(profile.maxDuration)}`;
    }
  }

  const trimmed = reason.trim();
  if (trimmed.length < REASON_MIN) {
    errors.reason = `Begründe den Zugriff mit mindestens ${REASON_MIN} Zeichen, idealerweise mit Ticket- oder Incident-Nummer.`;
  } else if (trimmed.length > REASON_MAX) {
    errors.reason = `Die Begründung darf höchstens ${REASON_MAX} Zeichen lang sein.`;
  }
  return errors;
}

function defaultDuration(profile: Profile): string {
  const max = parseDuration(profile.maxDuration) ?? 0;
  return (parseDuration('30m') ?? 0) <= max ? '30m' : profile.maxDuration;
}

export function RequestAccess() {
  const { api, profiles, access, navigate } = useAppData();
  const [step, setStep] = useState<Step>('form');
  const [profileName, setProfileName] = useState('');
  const [duration, setDuration] = useState('30m');
  const [reason, setReason] = useState('');
  const [showErrors, setShowErrors] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<ApiError>();
  const [created, setCreated] = useState<AccessEntry>();

  const profile = profiles.data?.find((p) => p.name === profileName);
  const errors = validate(profile, duration, reason);
  const hasErrors = Object.keys(errors).length > 0;

  const activeInNamespace = useMemo(
    () =>
      profile
        ? access.data?.find((e) => e.targetNamespace === profile.targetNamespace && statusOf(e).group === 'active')
        : undefined,
    [access.data, profile],
  );

  const presets = useMemo(() => {
    const max = profile ? parseDuration(profile.maxDuration) : null;
    return PRESETS.filter((p) => max === null || (parseDuration(p) ?? 0) <= max);
  }, [profile]);

  function selectProfile(name: string) {
    setProfileName(name);
    const next = profiles.data?.find((p) => p.name === name);
    if (next) setDuration(defaultDuration(next));
  }

  function reset() {
    setStep('form');
    setProfileName('');
    setDuration('30m');
    setReason('');
    setShowErrors(false);
    setSubmitError(undefined);
    setCreated(undefined);
  }

  async function submit() {
    if (!profile) return;
    setSubmitting(true);
    setSubmitError(undefined);
    try {
      const result = await api.createAccess({
        accessProfile: profile.name,
        duration: duration.trim(),
        reason: reason.trim(),
      });
      setCreated(result);
      setStep('done');
      void access.reload();
    } catch (err) {
      setSubmitError(err instanceof ApiError ? err : new ApiError(String(err), 0));
    } finally {
      setSubmitting(false);
    }
  }

  if (profiles.loading) return <Loading label="Profile werden geladen…" />;

  const header = (
    <PageHeader
      title="Zugriff anfordern"
      description="Zeitlich begrenzter, nachvollziehbarer Zugriff auf einen festgelegten Namespace, nur für den Incident, an dem du gerade arbeitest."
    />
  );

  if (profiles.error) {
    return (
      <div className={page.page}>
        {header}
        <Notice tone="danger" title="Profile konnten nicht geladen werden.">
          {profiles.error.message}
        </Notice>
      </div>
    );
  }

  const available = profiles.data ?? [];
  if (available.length === 0) {
    return (
      <div className={page.page}>
        {header}
        <div className={page.card}>
          <EmptyState icon="lock" title="Für deine Identität ist kein Profil freigegeben.">
            Wende dich an das Plattform-Team, wenn du für Incidents Zugriff benötigst.
          </EmptyState>
        </div>
      </div>
    );
  }

  if (step === 'done' && created) {
    const status = statusOf(created);
    const isRequest = created.kind === 'Request';
    return (
      <div className={page.page}>
        {header}
        <section className={page.card} aria-labelledby="done-title">
          <div className={page.cardBody}>
            <div className={styles.doneHead}>
              <span className={styles.doneIcon}>
                <Icon name="check" size={20} />
              </span>
              <div>
                <h2 id="done-title" className={page.sectionTitle}>
                  {isRequest ? 'Antrag eingereicht' : 'Self-Service-Zugriff angelegt'}
                </h2>
                <p className={page.sectionHint}>
                  Referenz <span className={page.mono}>{created.name}</span>
                </p>
              </div>
              <StatusBadge tone={status.tone} label={status.label} />
            </div>
            <Notice tone={isRequest ? 'warning' : 'info'}>
              {isRequest
                ? 'Ein Antrag ist noch kein Zugriff. Er wird erst nach einer unabhängigen Freigabe aktiv und verfällt, wenn niemand rechtzeitig entscheidet.'
                : 'Der Zugriff ist nutzbar, sobald unter „Meine Zugriffe“ der Status „Aktiv“ erscheint.'}
            </Notice>
          </div>
          <div className={page.actionsBar}>
            <Button onPress={reset}>Weiteren Zugriff anfordern</Button>
            <Button variant="primary" onPress={() => navigate('access')}>
              Zu meinen Zugriffen
            </Button>
          </div>
        </section>
      </div>
    );
  }

  if (step === 'review' && profile) {
    const isApproval = profile.deliveryMode === 'ApprovalRequired';
    const unclearOutcome = submitError && (submitError.status === 0 || submitError.status >= 500);
    return (
      <div className={page.page}>
        {header}
        <section className={page.card} aria-labelledby="review-title">
          <div className={page.cardBody}>
            <div>
              <h2 id="review-title" className={page.sectionTitle}>
                Angaben prüfen
              </h2>
              <p className={page.sectionHint}>Nach dem Absenden kannst du den Antrag nicht mehr ändern.</p>
            </div>
            <dl className={page.facts}>
              <dt>Profil</dt>
              <dd>{profile.name}</dd>
              <dt>Namespace</dt>
              <dd className={page.mono}>{profile.targetNamespace}</dd>
              <dt>Rolle</dt>
              <dd className={page.mono}>{profile.roleRef}</dd>
              <dt>Dauer</dt>
              <dd>{formatGoDuration(duration.trim())}</dd>
              <dt>Bereitstellung</dt>
              <dd>{isApproval ? 'Nach unabhängiger Freigabe' : 'Sofort (Self-Service)'}</dd>
              <dt>Begründung</dt>
              <dd className={page.reason}>{reason.trim()}</dd>
            </dl>
            <Notice tone={isApproval ? 'warning' : 'info'}>
              {isApproval
                ? 'Ein Antrag ist noch kein Zugriff. Eine andere berechtigte Person muss ihn freigeben.'
                : 'Kubernetes prüft deine Berechtigung beim Absenden und stellt den Zugriff dann sofort bereit.'}
            </Notice>
            {submitError && (
              <Notice tone="danger" title="Der Antrag wurde nicht angenommen." urgent>
                {submitError.message}
                {unclearOutcome &&
                  ' Prüfe unter „Meine Zugriffe“, ob der Antrag trotzdem angelegt wurde, bevor du ihn erneut stellst.'}
              </Notice>
            )}
          </div>
          <div className={page.actionsBar}>
            <Button onPress={() => setStep('form')} isDisabled={submitting}>
              <Icon name="arrowLeft" />
              Zurück
            </Button>
            <Button variant="primary" onPress={submit} isPending={submitting} isDisabled={submitting}>
              {submitting ? 'Wird übermittelt…' : isApproval ? 'Verbindlich beantragen' : 'Zugriff anlegen'}
            </Button>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className={page.page}>
      {header}
      <form
        className={page.card}
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          setShowErrors(true);
          if (!hasErrors) {
            setSubmitError(undefined);
            setStep('review');
          }
        }}
      >
        <div className={page.cardBody}>
          <RadioGroup
            value={profileName}
            onChange={selectProfile}
            isInvalid={showErrors && Boolean(errors.profile)}
            className={styles.profileGroup}
          >
            <Label className={page.sectionTitle}>Profil</Label>
            <Text slot="description" className={page.sectionHint}>
              Rolle, Namespace und Höchstdauer legt das Plattform-Team im Profil fest.
            </Text>
            <div className={styles.profiles}>
              {available.map((p) => (
                <Radio key={p.name} value={p.name} isDisabled={!p.isReady} className={styles.profileCard}>
                  <span className={styles.profileTop}>
                    <span className={styles.profileName}>{p.name}</span>
                    {p.isReady ? (
                      <StatusBadge
                        tone={p.deliveryMode === 'ApprovalRequired' ? 'warning' : 'info'}
                        label={p.deliveryMode === 'ApprovalRequired' ? 'Freigabe nötig' : 'Self-Service'}
                      />
                    ) : (
                      <StatusBadge tone="danger" label="Nicht einsatzbereit" />
                    )}
                  </span>
                  <span className={styles.profileDescription}>{p.description}</span>
                  <span className={styles.profileMeta}>
                    <span>
                      Namespace <strong className={page.mono}>{p.targetNamespace}</strong>
                    </span>
                    <span>
                      Max. <strong>{formatGoDuration(p.maxDuration)}</strong>
                    </span>
                  </span>
                </Radio>
              ))}
            </div>
            <FieldError className={fieldStyles.error}>{errors.profile}</FieldError>
          </RadioGroup>

          {activeInNamespace && (
            <Notice tone="info" title="Du hast hier bereits einen aktiven Zugriff.">
              Im Namespace <span className={page.mono}>{activeInNamespace.targetNamespace}</span> ist{' '}
              <span className={page.mono}>{activeInNamespace.name}</span> noch aktiv. Prüfe, ob ein weiterer Zugriff nötig
              ist.
            </Notice>
          )}

          <div className={styles.durationBlock}>
            <RadioGroup
              aria-label="Dauer schnell wählen"
              orientation="horizontal"
              value={presets.includes(duration.trim()) ? duration.trim() : ''}
              onChange={setDuration}
              className={fieldStyles.segmented}
            >
              {presets.map((p) => (
                <Radio key={p} value={p} className={fieldStyles.segment}>
                  {formatGoDuration(p)}
                </Radio>
              ))}
            </RadioGroup>
            <TextInputField
              label="Dauer"
              value={duration}
              onChange={setDuration}
              isRequired
              description={
                profile
                  ? `Höchstens ${formatGoDuration(profile.maxDuration)} · Format wie 45m oder 1h30m`
                  : 'Format wie 45m oder 1h30m'
              }
              error={showErrors ? errors.duration : undefined}
            />
          </div>

          <TextAreaField
            label="Begründung"
            value={reason}
            onChange={setReason}
            isRequired
            maxLength={REASON_MAX}
            description={
              <>
                Ticket- oder Incident-Nummer und kurz, was du prüfen willst. Keine Passwörter, Tokens oder anderen
                Geheimnisse eingeben. <span className={page.mono}>{reason.trim().length}/{REASON_MAX}</span>
              </>
            }
            error={showErrors ? errors.reason : undefined}
          />
        </div>
        <div className={page.actionsBar}>
          <Button type="submit" variant="primary">
            Weiter zur Prüfung
          </Button>
        </div>
      </form>
      <p className={page.muted}>Jeder Antrag wird mit deiner Kubernetes-Identität im Audit-Log erfasst.</p>
    </div>
  );
}
