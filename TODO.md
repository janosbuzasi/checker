# Checker TODO

Stand: 2026-07-23

## Aktueller Stand

Version 1.3.0 ist produktiv auf Plesk im Einsatz.

- [x] HTTP- und HTTPS-Erreichbarkeit pruefen.
- [x] HTTP-Status, Weiterleitungen und Header anzeigen.
- [x] TLS-Zertifikat, Laufzeit, Protokoll und Cipher auswerten.
- [x] Domainnamen ueber A- und AAAA-Records aufloesen.
- [x] Direkte oeffentliche IPv4- und IPv6-Adressen akzeptieren.
- [x] Private, reservierte, Loopback- und Link-local-Ziele blockieren.
- [x] Reverse DNS fuer ermittelte IP-Adressen anzeigen.
- [x] IP-Netz, Registrant und Abuse-Kontakt ueber RDAP anzeigen.
- [x] ASN, angekuendigtes Praefix und Registry ermitteln.
- [x] Ergebnisse als HTML und JSON bereitstellen.
- [x] Produktiv mit `8.8.8.8` und `bluewin.ch` getestet.

## Naechste Verbesserungen

### Performance und Timeouts

- [ ] HTTP-Statusabfrage ueberspringen, wenn der zugehoerige Port bereits als geschlossen erkannt wurde.
- [ ] Verbindungs-, HTTP-, TLS- und RDAP-Timeouts getrennt konfigurierbar dokumentieren.
- [ ] Standard-Timeout fuer nicht antwortende Ports pruefen und gegebenenfalls von 5 auf 3 Sekunden reduzieren.
- [ ] Unabhaengige Pruefungen nach Moeglichkeit parallel ausfuehren, sofern dies auf Shared Hosting stabil moeglich ist.
- [ ] Laufzeit der einzelnen Pruefschritte und die gesamte Pruefdauer im JSON-Ergebnis ausgeben.

### RDAP und Netzwerkdaten

- [ ] RDAP-Ergebnisse kurzzeitig cachen, damit wiederholte Abfragen derselben IP schneller werden.
- [ ] Bei nicht erreichbarem RDAP-Dienst eine deutlichere, aber weiterhin sichere Statusmeldung anzeigen.
- [ ] Optional Registrierungsdaten fuer alle aufgeloesten IP-Adressen statt nur fuer die erste Adresse anzeigen.
- [ ] Unterschiedliche ASN-Werte eines Multi-IP-Hosts sichtbar machen.

### Bedienung und Ausgabe

- [ ] Erklaeren, dass ein TLS-Zertifikatsfehler bei direkter IP-Eingabe normal sein kann.
- [ ] Lange laufende Pruefungen mit einem sichtbaren Ladezustand kennzeichnen.
- [ ] Zeitueberschreitungen in der Oberflaeche von anderen Verbindungsfehlern unterscheiden.
- [ ] Optional einzelne Pruefbereiche aktivieren oder deaktivieren.

## Deployment

Der Checker wird aus dem Branch `main` ueber Plesk bereitgestellt:

1. Aenderungen committen und zu GitHub pushen.
2. In Plesk `Jetzt Pull ausfuehren`.
3. In Plesk `Jetzt bereitstellen`.

Die Anwendung benoetigt keine Datenbank und keine Composer-Abhaengigkeiten. Fuer RDAP muss auf dem Server entweder HTTPS-Zugriff ueber `allow_url_fopen` funktionieren oder die PHP-cURL-Erweiterung verfuegbar sein.
