# 🔮 BreakGlass Operator – Zukunftsvision & Roadmap

> **Mission Statement**  
> Der **BreakGlass Operator** transformiert Kubernetes Access Management von einem statischen, überprivilegierten Modell (*„Entwickler haben permanente Admin-Rechte für Notfälle“*) in eine kompromisslose **Zero-Trust Just-In-Time (JIT) Privileged Access Management (PAM)** Plattform für Cloud-Native Workloads.

---

## 🏛️ Die Zukunftsvision: Vom Operator zur JIT-Plattform

In modernen Kubernetes-Umgebungen (SOC2, ISO 27001, PCI-DSS, FedRAMP) ist die permanente Vergabe von administrativen Rollen (`cluster-admin`, `edit`, `secrets`-Zugriff) ein kritisches Sicherheitsrisiko.

Der BreakGlass Operator schließt diese Lücke, indem er das **„Principle of Least Privilege“** automatisiert:
Standardmäßig besitzt niemand privilegierte Rechte. Bei Zwischenfällen wird der Zugriff temporär, begründet, freigegeben und lückenlos auditiert bereitgestellt – und nach Ablauf der TTL spurlos wieder entzogen.

```mermaid
flowchart TD
    subgraph Trigger["1. Request & Trigger"]
        A1["Developer / On-Call SRE"] -->|kubectl / ChatOps / Web UI| R["BreakGlassRequest"]
        A2["Incident Response Alert (PagerDuty)"] -->|Auto-Trigger| R
    end

    subgraph Governance["2. Policy & Admission Guardrails"]
        R --> V["Validating & Mutating Webhook"]
        V -->|Verify Ticket, Max Duration, 4-Eyes Principle| P{"Approval Engine"}
        P -->|Rejected / Invalid| DENY["Access Denied"]
    end

    subgraph Execution["3. JIT Provisioning (Core Controller)"]
        P -->|Approved| BGS["BreakGlassSession (Active)"]
        BGS --> RBAC["Dynamic RoleBinding / ClusterRoleBinding"]
        BGS --> T["Ephemeral Token / Kubeconfig"]
    end

    subgraph Observability["4. Telemetry, Drift & Audit"]
        BGS --> E["K8s Events & Prometheus Metrics"]
        BGS --> D["Drift Detection / Self-Healing"]
        BGS --> A["Kubernetes Audit Log Forensics"]
    end

    subgraph Revocation["5. Automated Deprovisioning"]
        BGS -->|TTL Expiry / Manual Revocation| EXP["Cleanup Controller"]
        EXP -->|Purge| RBAC
        EXP -->|Revoke| T
        EXP --> POST["Post-Mortem Audit Bundle (PDF / S3)"]
    end
```

---

## 🗺️ Die 5-Phasen-Roadmap

| Phase | Fokus | Hauptziel | Kerntechnologien |
| :--- | :--- | :--- | :--- |
| **Phase 1** *(Fertig)* | **MVP & Core Reliability** | Solide CRD-Basis, `RequeueAfter`-Lifecycle, Drift-Detection, Events | Kubebuilder, Controller-Runtime |
| **Phase 2** | **Guardrails & Admission Policies** | Validating/Mutating Webhooks, Ticket-Validierung, Max-TTL | Admission Webhooks, Cert-Manager |
| **Phase 3** | **Interactive Approvals & ChatOps** | 4-Augen-Prinzip, Slack/Teams Integration, Self-Service CLI | Slack API / Webhooks, CLI-Plugin |
| **Phase 4** | **Audit Trail & Forensik** | Was hat der User während der Session getan? Audit-Log Korrelation | K8s Audit Logs, OpenTelemetry |
| **Phase 5** | **Zero-Trust Identity Federation** | Kurzlebige Tokens statt statischer User, Cloud-IAM Bridging | OIDC, Ephemeral SAs, Vault |

---

### Phase 1: MVP & Core Reliability *(Abgeschlossen)*
* [x] **CRD-Design**: `BreakGlassSession` mit Support für Namespaced (`RoleBinding`) und Cluster-Scoped (`ClusterRoleBinding`).
* [x] **TTL Controller**: Exakte Berechnung von `requeueAfter` ohne Worker-Threads zu blockieren.
* [x] **Self-Healing & Drift Detection**: Wiederherstellung gelöschter Bindings in Echtzeit.
* [x] **Audit Events**: Native K8s-Events (`AccessGranted`, `AccessExpired`, `AccessRevoked`).
* [x] **Finalizer-Pattern**: Sauberes Aufräumen aller K8s-Objekte bei Deletion.

---

### Phase 2: Admission Governance & Guardrails
> **Ziel:** Verhindern, dass Entwickler die CRD missbrauchen, um sich unbeaufsichtigt unbegrenzte Rechte zu verschaffen.

* **Validating Admission Webhook**:
  * **Max-Duration Enforcer**: Z. B. `cluster-admin` maximal für 1h, gewöhnliche Rollen maximal für 4h.
  * **Protected Roles Blacklist**: Rollen wie `system:masters` oder Zugriffe auf Kube-System können komplett gesperrt werden.
  * **Ticket-ID Validierung**: Das Feld `reason` muss einem RegEx-Muster entsprechen (z. B. `^(INC|CHG|SEC)-[0-9]+$`).
* **Mutating Admission Webhook**:
  * **Identity Attribution**: Automatisches Auslesen des echten aufrufenden API-Users (`admissionv1.Request.UserInfo`) und Festschreiben in `spec.subject`, damit sich niemand als ein anderer User ausgeben kann.
* **Kustomize & Helm Chart**:
  * Offizielles Helm-Chart inklusive Cert-Manager-Integration für Webhook-Zertifikate.

---

### Phase 3: Interactive Approvals & ChatOps (4-Augen-Prinzip)
> **Ziel:** Notfallzugriff erfordert in Produktivsystemen oft die Freigabe eines zweiten Engineers oder Security-Offiziers.

* **Entkopplung in Request & Session**:
  * Neue CRD `BreakGlassRequest` $\rightarrow$ Prüfung $\rightarrow$ Operator erzeugt `BreakGlassSession`.
* **ChatOps / Slack & Teams Integration**:
  * Wird ein Request erstellt, sendet der Operator eine Benachrichtigung in einen Alert-Channel:
    > *„@yannick beantragt `cluster-admin` für 30m wegen Notfall INC-1092. [Approve] [Deny]“*
  * Bei Klick auf *Approve* schaltet der Operator die Session frei.
* **`kubectl breakglass` CLI-Plugin (Krew)**:
  * Ein interaktives Tool für Entwickler:
    ```bash
    kubectl breakglass request --role cluster-admin --duration 30m --reason "INC-404"
    # Wartet auf Freigabe... Genehmigt! Session aktiv bis 11:30.
    ```

---

### Phase 4: Observability, Metriken & Forensik
> **Ziel:** Volle Transparenz für Security Audits und Incident Reviews.

* **Prometheus Metriken**:
  * `breakglass_active_sessions`: Gauge der aktuell aktiven Notfallsitzungen.
  * `breakglass_sessions_total{role, subject, phase}`: Zähler für alle durchgeführten Eskalationen.
  * `breakglass_drift_detected_total`: Anzahl der erkannten Manipulationsversuche an Bindings.
* **Grafana Dashboard**:
  * Heatmap: Wann finden die meisten Notfallzugriffe statt?
  * Welche Rollen und Namespaces werden am häufigsten angefordert?
* **Kubernetes Audit-Log Korrelation**:
  * Nach Ablauf einer Session fasst der Operator zusammen: Welche `kubectl`-Befehle / API-Calls wurden von dem User im Zeitfenster zwischen `startTime` und `expiresAt` tatsächlich abgesetzt?
  * Export als Audit-Report (z. B. Markdown in ConfigMap oder JSON an S3/SIEM).

---

### Phase 5: Zero-Trust & Identity Federation
* **Kurzlebige Ephemeral ServiceAccounts & Kubeconfigs**:
  * Statt existierende Accounts zu berechtigen, erzeugt der Operator einen temporären, nur für die Dauer der Session existierenden ServiceAccount inklusive zeitlich begrenztem Token.
* **Cloud Provider IAM-Bridging**:
  * Kopplung mit Cloud-Rechten (z. B. AWS IRSA, GCP Workload Identity): Wenn Break-Glass aktiv ist, wird auch der Zugriff auf Cloud-Ressourcen (z. B. RDS-Datenbank) temporär freigeschaltet.

---

## 🏆 Warum dieses Projekt hervorsticht
1. **Kein Spielzeug**: Löst ein akutes Problem, das fast jedes Unternehmen in Produktiv-Clustern hat (Least-Privilege vs. Notfallzugriff).
2. **Vorzeige-Architektur**: Zeigt tiefes Beherrschen von Kubebuilder, Controller-Runtime Caches, Informern, Finalizern, Webhooks und RBAC-Interna.
3. **Open-Source Potenzial**: Ähnlich wie Tools wie `teleport` oder `boundary`, aber native-first als leichtgewichtiger Kubernetes-Operator.
