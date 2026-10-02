## UI/UX-Konzept: optionale WebUI für den BreakGlass Operator

**Empfehlung vorab:** Die UI sollte noch nicht implementiert werden. Sie ist fachlich wertvoll, aber erst nach zwei Voraussetzungen produktionsreif:

1. `BreakGlassRequest → BreakGlassApproval → BreakGlassSession` muss vollständig, idempotent und fail-closed funktionieren.
2. Es braucht eine explizite Lösung für **datensichere „Meine Anträge“-/Approval-Inbox-Ansichten**. Die aktuellen clusterweiten CRDs lassen sich mit Kubernetes-RBAC nicht zeilenweise nach `spec.requester` filtern. Ein simples `list` würde sensible Gründe und Identitäten anderer Personen offenlegen. Das wäre ein P0-Designproblem, keine UI-Detailfrage.

Das Konzept wahrt damit die bestehende Invariante: Ein kuratiertes Profil erzeugt genau eine UID-überwachte namespaced `RoleBinding`; keine Komfortfunktion darf einen zweiten Grant-Pfad schaffen. [Produktvision](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/product-vision.md:22), [Security Design](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/security-design.md:40)

### Produktziel und Leitprinzipien

Die WebUI ist ein optionaler, menschlicher Client für den Request-Workflow, nicht Teil der RBAC-Provisionierung:

```text
Browser
  → OIDC-Login
  → UI / user-bound API flow
  → BreakGlassRequest / BreakGlassApproval
  → Operator-Controller
  → BreakGlassSession
  → namespaced RoleBinding
```

Sie darf niemals:

- `RoleBinding` oder `ClusterRoleBinding` erstellen, ändern oder löschen;
- den Manager-ServiceAccount, `cluster-admin` oder breit berechtigte Kubeconfig-Dateien nutzen;
- als menschliche Person impersonieren;
- eine eigene Approval-Datenbank, Rollenlogik oder „Sofortzugriff“-Hintertür etablieren;
- freie Rolle, Namespace, Zielperson oder TTL erlauben.

Der einzige Grant-Erzeuger bleibt der Controller. Das entspricht der bestehenden Request-Architektur. [Request-Design](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/breakglass-request-design.md:7)

## Zielgruppen und ihre Jobs

| Persona | Aufgabe in der UI | Darf nicht |
|---|---|---|
| On-call Engineer | Profil prüfen, begründeten Antrag stellen, eigenen Status sehen, aktiven Zugriff früh widerrufen | Rollen/Namespaces wählen, andere Anträge einsehen, selbst freigeben |
| Approver | Antrag prüfen, approve/deny mit nachvollziehbarer Entscheidung | eigenen Antrag freigeben, Session oder RBAC direkt erzeugen |
| Incident Commander / Security | Ausnahme- und Betriebsstatus bewerten, in Audit/SIEM springen | Profil- oder RBAC-Policy über die UI verändern |
| Auditor | Nachweisorientierte Recherche über den abgesicherten Audit-Kanal | operative Freigaben oder Änderungen ausführen |
| Platform Owner | GitOps-Profile und Deployment-Grenzen pflegen | UI als Ersatz für versionierte Policy-Autorenschaft verwenden |

Die Trennung zwischen Requester, Approver, Auditor, Profilautor und Controller ist bereits ein explizites Sicherheitsziel. [Request-Design](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/breakglass-request-design.md:43), [Security Review](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/security-review.md:90)

## Informationsarchitektur

Die Navigation richtet sich nach der aktuell verifizierten Rolle, nicht nach einer UI-eigenen Rollenverwaltung:

```text
BreakGlass
├── Zugriff anfordern
│   ├── Policy-Vorabprüfung
│   └── Antrag bestätigen
├── Meine Anträge
│   └── Antrag / Session-Detail
├── Freigabe-Inbox              (nur Approver, später)
│   └── Antrag prüfen / Approve / Deny
├── Betriebsübersicht           (nur Security/Platform, read-only)
│   ├── aktive/überfällige Sessions
│   ├── Drift / Webhook / Cleanup
│   └── Link zu Grafana und Runbooks
└── Hilfe
    ├── Offline-Notfallverfahren
    ├── Status-Legende
    └── Datenschutz / Audit-Hinweis
```

**Nicht** in die Navigation gehören Profileditor, RBAC-Editor, Cluster-Explorer, Secret-Browser oder ein universeller Kubernetes-Proxy.

## Screens und Interaktionen

### 1. Start / Zugriff anfordern

Ziel: Unter Stress schnell helfen, ohne gefährliche Auswahlmöglichkeiten anzubieten.

```text
[ BreakGlass – temporären Zugriff anfordern ]

Profil
[ production-pod-observer                    v ]

Gewährt: Pods, Events und Logs lesen
Geltungsbereich: production
Maximaldauer: 30 Minuten
Kein Zugriff auf Secrets, exec, Port-Forward oder Änderungen.

Dauer
[ 20 Minuten                                  ]

Incident-Grund *
[ INC-1092 – Datenbank-Verbindungen prüfen   ]

[ Vorab prüfen ]          [ Antrag stellen ]
```

Verhalten:

- Das UI zeigt **Capability-Sprache**, nicht rohe RBAC-Regeln als primäre Sprache.
- „Vorab prüfen“ ist rein informativ und niemals verbindlich. Die finale Prüfung bleibt Admission + `SubjectAccessReview`.
- Die Profil-, Namespace-, Rollen- und TTL-Grenze kommt ausschließlich aus `AccessProfile`; das UI setzt sie nicht durch.
- Der Grund wird deutlich als sensibel markiert: keine Zugangsdaten, Tokens oder Geheimnisse eingeben.
- Die finale Bestätigung enthält Profil, effektiven Zielbereich, Dauer, Grund und den Hinweis: „Ein Antrag ist noch kein Zugriff.“

`AccessProfile` ist dafür die richtige Policy-Quelle: Rolle, Zielnamespace und maximale Dauer sind bereits fest verdrahtet und unveränderlich. [AccessProfile API](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/api/v1alpha1/accessprofile_types.go:24)

**Wichtige Einschränkung:** Ein UI darf aktuell nicht einfach alle `AccessProfile` auflisten. Schon die Profilnamen oder Zielumgebungen können sensibel sein; außerdem ist `use` keine Leseberechtigung. Für eine echte Profilauswahl braucht es später eine explizite, nicht-authoritative Catalog-/Projection-Lösung oder ein bewusst freigegebenes, begrenztes Profilverzeichnis. Bis dahin: bekanntes Profil eingeben oder einen aus dokumentierten Team-Runbooks kommenden Link verwenden.

### 2. Antrag erfolgreich erstellt

```text
[ Antrag eingereicht ]

Status: Wartet auf Freigabe
Referenz: bgr-01J...
Profil: Production Pod Observation
Angefragt: 20 Minuten
Erstellt: 09:18:04 CEST

Der Antrag gewährt noch keinen Zugriff.
Wir benachrichtigen dich, wenn sich sein Status ändert.

[ Referenz kopieren ] [ Zu meinen Anträgen ]
```

- Die UI zeigt ausschließlich serverbestätigte Daten.
- Kein Optimismus-Bias wie „Zugriff wird gleich aktiv“.
- Bei unklarer Netzwerkantwort: **nicht erneut automatisch absenden**. Stattdessen: „Der Status ist unbekannt. Suche zuerst nach der Referenz.“  
  Dafür sollte die spätere API eine requester-gebundene Idempotenzstrategie erhalten; `generateName` allein schützt nicht gegen Doppelanträge.

### 3. Meine Anträge / Detail

```text
[ Meine Anträge ]

INC-1092 · Production Pod Observation
Status: Waiting for approval
Angefragt: 20m · erstellt vor 4m
[ Details ]

INC-1088 · Production Pod Observation
Status: Active · endet in 12:31
[ Zugriff prüfen ] [ Zugriff widerrufen ]
```

Detailansicht mit klarer Timeline:

```text
Antrag erstellt        09:18
Freigegeben            09:20
Session aktiv          09:20
Endet                  09:40
Status                 Active

[ Zugriff jetzt prüfen ]       [ Zugriff widerrufen ]
```

- Countdown ist sekundär; maßgeblich ist der vom Server gespeicherte Ablaufzeitpunkt.
- „Zugriff widerrufen“ fordert eine explizite Bestätigung und nutzt später ausschließlich den bereits erlaubten, einseitigen `spec.revoked: true`-Pfad über die Identität des Nutzers.
- Bei `Suspended` gibt es keine „Reparieren“-Schaltfläche. Die UI erklärt: Zugriff wurde aus Sicherheitsgründen entfernt; Audit/Runbook prüfen. Das entspricht dem fail-closed Drift-Modell. [Session API](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/api/v1alpha1/breakglasssession_types.go:189), [Security Design](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/security-design.md:89)

### 4. Freigabe-Inbox — später

```text
[ Freigabe erforderlich ]

INC-1092 · Production Pod Observation
Requester: Max Mustermann
Dauer: 20 Minuten
Bereich: production
Grund: Datenbank-Verbindungen prüfen
Antrag läuft ab in: 06:12

[ Ablehnen ]                         [ Freigeben ]
```

Bei „Freigeben“:

```text
Du gibst einen zeitlich begrenzten, namespaced Zugriff frei.

[ ] Ich bin nicht der Antragsteller.
[ ] Ich habe Profil, Dauer und Incident-Kontext geprüft.

Kommentar (optional)
[ … ]

[ Freigabe verbindlich abgeben ]
```

Der Button erzeugt später nur eine append-only `BreakGlassApproval` über die authentifizierte Person. Die Approval-Webhook-Prüfung muss Self-Approval, stale Request-UID, Ablauf, Replay und fehlende Berechtigung ablehnen. [Request-Design](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/breakglass-request-design.md:25)

### 5. Betriebsübersicht — bewusst keine Forensik-Konsole

Für Platform/Security:

- Anzahl aktiver und überfälliger Sessions;
- Drift-, Cleanup- und Admission-Fehler als aggregierte Ampeln;
- Webhook-/Controller-Gesundheit;
- Links zu Grafana, Runbooks und dem geschützten SIEM-Fall.

Keine Namen, Gründe, Ticketnummern, Rollen, Namespace-Namen oder Session-IDs in Prometheus-Diagrammen. Genau diese Privacy-/Cardinality-Grenze existiert bereits im Operator. [Observability](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/observability.md:13)

## Fehler-, Leer- und Sicherheitszustände

| Zustand | UX-Verhalten |
|---|---|
| Nicht angemeldet / Token abgelaufen | „Anmeldung erneuern“; nie stillschweigend mit ServiceAccount fortsetzen |
| OIDC-Identität passt nicht zum Kubernetes-User | Zugriff blockieren, technische Support-Referenz zeigen, keine alternative Identität anbieten |
| Kein verfügbares Profil | „Für deine Identität ist kein freigegebenes Profil verfügbar“; keine Profile aufzählen |
| Dauer zu hoch / Profil nicht bereit | Konkreten, aber nicht sensiblen Hinweis anzeigen; serverseitige Entscheidung ist verbindlich |
| Admission/Webhook nicht erreichbar | „Neue Zugriffe können aus Sicherheitsgründen nicht angefordert werden.“ Link zum dokumentierten Offline-Prozess, nie „trotzdem fortfahren“ |
| Antrag abgelaufen | Deutlich beendet; „Neuen Antrag mit aktuellem Incident-Kontext stellen“ |
| `Denied` | Entscheidung, Zeit und ggf. freigegebener Kommentar; kein Umgehungslink |
| `Suspended` | „Zugriff wurde entfernt, weil die Integrität nicht nachweisbar war.“ Runbook-/SIEM-Link, keine automatische Neuaktivierung |
| Session abgelaufen/revoked | Schreibgeschützter Nachweis, sichtbare Bestätigung, kein „Reaktivieren“-Button |
| Unklare Submit-Antwort | Wiederholung stoppen, Referenz/Status ermitteln, doppelte Grants verhindern |

## Authentifizierung und Berechtigungsgrenze

### Empfohlenes Zielmodell: OIDC-BFF mit user-bound Kubernetes-Aufrufen

1. Der Browser meldet sich über Authorization Code + PKCE beim bestehenden OIDC-Provider an.
2. Ein schlankes BFF hält eine kurzlebige, serverseitige Sitzung mit Secure/HttpOnly/SameSite-Cookie.
3. Für schreibende Kubernetes-Aktionen leitet es **ausschließlich einen kurzlebigen, Kubernetes-audience-gebundenen Benutzer-Token** weiter.
4. Kubernetes authentifiziert, autorisiert und auditiert die Person erneut. Der BFF trifft keine Grant-Entscheidung und impersoniert niemanden.
5. Der BFF hat weder Manager-Credentials noch `bind`, Session-, RoleBinding- oder ClusterRoleBinding-Rechte.

Das schließt an die vorhandene Authentifizierungsgrenze an: Admission übernimmt den Subject aus `AdmissionRequest.userInfo` und prüft die profilgebundene `use`-Berechtigung selbst. [Request Webhook](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/internal/webhook/v1alpha1/breakglassrequest_webhook.go:23)

**Explizit nicht akzeptabel:**

- Browser-Tokens in `localStorage`;
- ein BFF mit `cluster-admin`;
- ein ServiceAccount, der Benutzer imitiert;
- ein „UI-Admin“-Konto als versteckter zweiter Zugriffsweg;
- direkte Browser-Calls an die Kubernetes-API ohne überprüfte CORS-, Token-Audience- und CSP-Konfiguration.

### Das offene P0-Thema: private Listen und Inboxes

Die neue `BreakGlassRequest`-CRD ist cluster-scoped und enthält Requester, Profil, Dauer und Grund. [Request API](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/api/v1alpha1/breakglassrequest_types.go:10) Kubernetes RBAC kann nicht ausdrücken: „Liste nur Objekte, deren `spec.requester.name` meiner Identität entspricht.“

Daher dürfen wir **nicht** einfach `list/get/watch` an alle Requester oder Approver vergeben. Das wiederholt genau den bereits dokumentierten Schutzbedarf für Identität und Incident-Gründe. [Threat Model](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/threat-model.md:9), [Security Review SR-05](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/security-review.md:74)

Es gibt drei bewusste Optionen:

1. **Pilot mit bewusst breiter, eingeschränkter On-call-/Approver-Gruppe:** technisch simpel, aber nur akzeptabel, wenn Sichtbarkeit aller Anträge innerhalb dieser Gruppe ausdrücklich gewollt und dokumentiert ist.
2. **Read-only UI-Facade:** eigener, separat geprüfter ServiceAccount mit nur Leserechten auf Request/Approval/Session; der Dienst filtert strikt auf OIDC-Identität bzw. nach verifiziert zuständigem Approver-Profil. Schreibvorgänge bleiben user-bound. Das ist kein Grant-Pfad, aber ein neues Datenschutz-/Autorisierungsmodul und braucht Threat Model, Audit, Rate Limits und Tests.
3. **API-Redesign vor v1beta1:** namensraumbezogene Request-Ressourcen oder ein explizites, authorisiertes Request-Read-API. Das ist langfristig am klarsten, aber größer.

Meine Empfehlung: **Option 2 erst als separates, sicherheitsreviewtes UI-Facade-Subprojekt**, nachdem der Approval-Workflow stabil ist. Bis dahin keine „My Requests“- oder Inbox-Funktion versprechen.

## Berechtigungsmodell

| Komponente / Rolle | Lesen | Schreiben | Verboten |
|---|---|---|---|
| Requester | eigener Verlauf nur über genehmigte Sichtbarkeitslösung | `create BreakGlassRequest`, später eigene Revocation über user-bound API | Approvals, Sessions, RBAC |
| Approver | nur zuständige Requests über dieselbe Sichtbarkeitslösung | `create BreakGlassApproval` | eigene Requests freigeben, Sessions/RBAC |
| UI-BFF | keine privilegierten Kubernetes-Schreibrechte | keine | `bind`, RoleBinding, Session, Approval als ServiceAccount |
| UI-Read-Facade, falls gewählt | eng begrenztes read-only auf die drei CRDs | keine | alle RBAC-Objekte, Secrets, Writes |
| Controller | Request-zu-Session-Pfad laut späterer serverseitiger `requestRef`-Prüfung | genau eine Session pro genehmigtem Request | freies Session-Erzeugen |
| Platform Admin | GitOps-Repo, Profile, Deployment | policy-/deploymentbezogen | operativen UI-Bypass |
| Auditor | Audit/SIEM, bewusst eingeschränkte CR-Leseansicht | keine | Requests, Approvals, Grants |

## Deployment und Aktivierung

Die UI soll ein **separates optionales Paket** erhalten, etwa `config/overlays/webui`, niemals stillschweigend Teil des Default-Installers sein.

Aktivierungskriterien:

- `ui.enabled: false` als Default;
- separate Deployment-, ServiceAccount-, NetworkPolicy- und Image-Supply-Chain;
- eigener Namespace, etwa `breakglass-operator-ui`;
- UI-ServiceAccount ohne Manager-RBAC und ohne automountetes ServiceAccount-Token, soweit nicht für den read-only Facade-Dienst zwingend;
- Bild per Digest gepinnt, signiert, SBOM/Scan wie der Operator;
- egress nur zu OIDC-Provider und Kubernetes-API; keine Verbindung zum Manager-Pod und keine Secrets-/RBAC-APIs;
- TLS am Ingress, HSTS, CSP `frame-ancestors 'none'`, strenge `connect-src`, keine Drittanbieter-Tracker;
- Deinstallation der UI beeinflusst weder Active Sessions noch Operator/Webhooks;
- Start-Preflight prüft OIDC issuer, erwartete audience, HTTPS-Origin, API-Erreichbarkeit, Audit-Sink und den gewählten Request-Visibility-Modus.

Der UI-Schalter darf nur die UI bereitstellen. Er darf **nicht** Admission lockern, Requester-RBAC erweitern oder den Operator in einen anderen Sicherheitsmodus setzen.

## Audit und Datenschutz

- Kubernetes Audit und der eingeschränkte SIEM-Sink bleiben die forensische Wahrheit; kein zweiter Audit-CRD und kein UI-eigener, dauerhafter Incident-Speicher. [Produktvision](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/product-vision.md:100)
- UI-Audit protokolliert minimal: Login-/Logout-Erfolg, Submission-/Approval-Versuch, Ergebnisfamilie, Request-Referenz und Korrelation. Keine Gründe, Tokens, vollständigen Request-Bodies, Profile oder Namen in normalen App-Logs.
- Antworten erhalten `Cache-Control: no-store`; Screenreader-/Browser-Verlauf darf keinen Incident-Grund persistieren.
- Für Audit-/Security-Ansichten: maskierte Werte standardmäßig, „sensiblen Grund anzeigen“ nur mit eigener Berechtigung und nachvollziehbarer UI-Audit-Action.

## Accessibility und Stress-UX

Mindestziel: WCAG 2.2 AA.

- Vollständig per Tastatur bedienbar; sichtbarer Fokus, logische Tab-Reihenfolge, Escape schließt Dialoge.
- Keine Information nur über Farbe; Status hat Text, Icon und Screenreader-Label.
- Formulare zeigen Fehler direkt am Feld und zusätzlich in einer fokussierten Zusammenfassung.
- Zeitangaben enthalten lokale Zeit, Zeitzone und absolute Uhrzeit; Countdown ist nie alleinige Quelle.
- Statuswechsel mit zurückhaltenden `aria-live`-Hinweisen; kein störendes Dauer-Ansagen des Countdowns.
- Mobile-tauglich für On-call, aber keine Abkürzung von Bestätigungen auf kleinem Bildschirm.
- Verständliche Sprache: „Zugriff aktiv bis …“ statt „Reconciliation succeeded“.

## Messbare Erfolgskennzahlen

Die UI misst Produktqualität, nicht Personen oder Incident-Inhalte:

- Zeit von erfolgreicher Anmeldung bis zu einem valideren Antrag;
- Zeit von Approval bis Session `Active`;
- Anteil klar aufgelöster Submit-Fehler ohne Doppelantrag;
- Anteil erfolgreicher Frühwiderrufe;
- Anteil `Suspended`-/Ablauf-Zustände, die innerhalb des SLO triagiert werden;
- Accessibility-Task-Erfolgsquote in Usability-Tests;
- UI-Verfügbarkeit, OIDC-Fehlerquote, API-/Webhook-Fehlerquote;
- Anteil der aktiven Production-Responder ohne dauerhafte privilegierte Rechte als North-Star-Metrik.

Keine Person, Ticket-ID, Grund, Namespace, Rollen- oder Profilname als Prometheus-Label. Die vorhandenen Metrikregeln sind dafür das Vorbild. [Observability](/Users/yannickchristianthomas/Documents/Codex/2026-09-25/referenced-chatgpt-conversation-this-is-an/work/breakglass-operator/docs/observability.md:13)

## Rollout in Phasen

| Phase | Umfang | Eintrittskriterium |
|---|---|---|
| 0 – Architektur | Visibility-Modell, OIDC-Mapping, Token-Audience, UI-Threat-Model, API-Idempotenz festlegen | Keine breiten CR-Leserechte für Requester |
| 1 – API-Fundament | Request TTL, Status-Lifecycle, `BreakGlassApproval`, `requestRef`, einmalige Session-Erzeugung, fail-closed E2E | Self-approval, stale UID, replay, expiry und Controller-Restart getestet |
| 2 – Read-only Pilot | Optionaler Betriebsstatus für Security/Platform, keine Requester-Inbox | Keine neue Grant-Berechtigung |
| 3 – Requester UI | Antrag, policy preview, private eigene Historie über gewählte Sichtbarkeitslösung, Revocation | OIDC-/CSP-/CSRF-/privacy-E2E und unabhängiges Security Review |
| 4 – Approval UI | Zuständigkeits-Inbox, append-only Approvals, keine Self-Approval | Approval- und Sichtbarkeitsmodell E2E-validiert |
| 5 – Erweiterungen | ChatOps/CLI als gleichwertige Clients, Ticket-/On-call-Integration | Kein Client kann RBAC direkt ändern |

## Konkrete nächste Schritte

1. Den **Request-Visibility-Entscheid** als P0 in das Request/Approval-Design aufnehmen; keine UI vor dieser Entscheidung.
2. `BreakGlassApproval` und den serverseitig validierten `requestRef`-Pfad implementieren.
3. Request-TTL, eindeutige Statusbedingungen, Idempotenz und eine sichere Referenz zur resultierenden Session ergänzen.
4. Ein eigenes UI-Threat-Model schreiben: Tokenfluss, Read-Facade, Logging, CSP/CSRF, OIDC-Gruppenmapping, Offlineszenario.
5. Erst danach ein klickbares Low-Fidelity-Prototyping mit fünf Screens: Request, Confirmation, My Requests, Approval, Suspended/Outage.

Die wichtigste UX-Entscheidung lautet damit: **Die UI beschleunigt sichere Abläufe; sie darf niemals aus einer menschlichen Stresssituation einen neuen privilegierten Systempfad machen.**