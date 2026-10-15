# Helm- und WebUI-Roadmap

Ziel: Ein Team kann dauerhafte Produktionsrechte durch zuverlässig nutzbaren,
temporären Zugriff ersetzen. Ein Meilenstein gilt erst mit dem dokumentierten
Nachweis als abgeschlossen; implementierter CI-Code allein ist kein bestandener
Cluster- oder Veröffentlichungstest.

| Meilenstein | Ergebnis | Abnahme |
| --- | --- | --- |
| M1 – Verlässlich installierbar | Helm, passende Operator-/WebUI-Images, Beispiele und abgesicherte Release-Paketierung | Grüner CI-Lauf einschließlich Kind; frische Installation mit den daraus veröffentlichten Artefakten |
| M2 – Lokale Demo | Kind, lokaler OIDC-Provider, HTTPS und drei Beispielidentitäten | Ein Befehl stellt eine benutzbare Umgebung bereit und kann sie wieder entfernen |
| M3 – Zugriffsablauf nachgewiesen | Authentifizierter Browser-Antrag, unabhängige Freigabe, echter API-Zugriff und Entzug | Positive und negative E2E-Tests prüfen Requester, Approver und unberechtigte Person |
| M4 – Betrieb beherrschbar | Audit, Alerts, Runbooks, Rotation und Versionswechsel | Betreiber erkennen und beheben Fehler bei weiterhin wirksamer Zugriffskontrolle |
| M5 – Begrenzter Pilot | Ein Team, wenige Namespaces, zunächst lesende Profile | Dauerhafte Rechte werden tatsächlich entfernt und der temporäre Weg bewährt sich |

## M1: Umsetzung und noch erforderlicher Nachweis

Implementiert:

- Namespaced Helm-RBAC, verpflichtende Webhooks, separater Expiry-Guard und
  gemeinsame Manifestprüfungen mit Kustomize.
- Main-CI baut und scannt beide amd64/arm64-Images; SBOM und Build-Provenance
  werden angehängt. Ein Release verlangt erfolgreiche Main-CI für genau den
  Tag-Commit.
- Der erfolgreiche CI-Lauf liefert ein checksummiertes Bundle. `release.json`
  enthält Quellrevision, Chart-/App-Version und beide Image-Digests. Die
  Release-Pipeline übernimmt diese Digests statt später veränderbarer SHA-Tags.
- Das veröffentlichte Chart enthält beide Digests. WebUI-Aktivierung erfordert
  eine passende OIDC-/HTTPS-Konfiguration, aber keinen separaten Image-Build.
- Gepflegte [lokale](../charts/breakglass-operator/examples/values-local.yaml)
  und [Produktions-Values](../charts/breakglass-operator/examples/values-production.yaml).
- Kind-Läufe verwenden private Kubeconfigs, explizite Testkontexte, JUnit und
  Diagnoseartefakte. Fehler lassen den isolierten Cluster für die Untersuchung
  bestehen; erfolgreiche Läufe räumen ihn auf.
- Die bekannte HTTP/2-Abhängigkeit wurde aktualisiert. Browser-Regressionen für
  Tastatur-Fokus und den mobilen Überlauf werden durch Tests abgedeckt.

Abnahme noch offen, bis die Belege vorliegen:

- [ ] Geprüften Commit auf GitHub bereitstellen und alle erforderlichen CI-Gates
  einschließlich der drei echten Kind-Läufe bestehen lassen.
- [ ] Beide Container-Builds und Image-Scans auf diesem Commit erfolgreich
  ausführen; lokales Go-Kompilieren ersetzt keinen Container-Build.
- [ ] Erstes versioniertes Chart samt beiden Images und `release.json`
  veröffentlichen; Paketlesbarkeit für den Zielcluster prüfen.
- [ ] Mit diesen Artefakten in einem frischen Cluster installieren und eine
  harmlose Session bis zum bestätigten Rechteentzug ausführen.
- [ ] Nur die tatsächlich belegte Kubernetes-/Kind-/cert-manager-Kombination
  nach dem bestehenden Kompatibilitätsverfahren dokumentieren.

Es werden keine Signatur-, OIDC-Integrations-, Multi-Cluster- oder
versionsübergreifenden Rollback-Garantien aus M1 abgeleitet. Die WebUI bleibt
bis zur konfigurierten Identitätsanbindung optional; die vollständige lokale
OIDC-Demo gehört zu M2.

## M3-Referenzszenario

Alice beantragt 15 Minuten Pod-Log-Zugriff für einen Incident. Bob genehmigt.
Charlie kann den Antrag weder lesen noch verändern. Alice kann Logs lesen,
aber keine Secrets. Nach Ablauf ist ihr Log-Zugriff nachweislich entzogen.

Der Pilot misst Zeit bis zum nutzbaren Zugriff, Cleanup-Lag, fehlgeschlagene
Anträge und tatsächlich entfernte dauerhafte Berechtigungen. CLI,
Incident-/On-call-Integration, kontrollierte Verlängerung und Multi-Cluster
werden anhand des Piloten priorisiert.
