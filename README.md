# zeek-capture-krejci

Eigenstaendiger, kurzlebiger **Zeek Passive Capture**-Stack fuer die Ground-Truth-
Messung der Bachelorarbeit (Kap. 3.3.1). Laeuft in Portainer **neben** dem
Condition-Monitoring-Stack, ohne ihn anzufassen. Erzeugt nur `conn.log`
(Kommunikationsmatrix) -- kein pcap, keine Inhalts-/Domain-Logs (Datenschutz, Kap. 3.5).

## Deploy (Portainer Git-Stack, kein SSH/Konsole noetig)
1. **DSM File Station:** Ordner `/volume1/docker/zeek-capture/logs` anlegen,
   Rechte auf Lesen/Schreiben setzen.
2. **Portainer -> Stacks -> Add stack:**
   - Build method: **Repository**
   - Repository URL: dieses Repo
   - Reference: `refs/heads/main`
   - Compose path: `docker-compose.yml`
   - (optional) Env `CAPTURE_IFACE` (Default `any`)
   - **Deploy**
3. Nach spaeteren Repo-Pushes in Portainer **Pull and redeploy** (oder Auto-Update).

## Laufzeit
Live laufen lassen bis Saettigung (2-3 Tage keine neuen Kommunikationspaare).

## Auswerten (am PC, ohne Konsole)
`conn.log` liegt im Netzwerkordner unter `docker/zeek-capture/logs/`. Herunterladen;
es ist eine Tab-getrennte TSV mit u. a. `id.orig_h`, `id.resp_h`, `id.resp_p`, `service`.
Nach (Quelle, Ziel, Zielport) gruppieren -> Kommunikationsmatrix -> gegen die
dokumentierte Soll-Kommunikation abgleichen.

## Aufraeumen
Stack in Portainer loeschen -- der CM-Stack bleibt unberuehrt. Logs im
Netzwerkordner bleiben, bis manuell geloescht.

## Hinweise
- `network_mode: host` + `NET_RAW`/`NET_ADMIN` sind zum Mitlesen noetig.
- Fuer die dokumentierte Endfassung Image-Version pinnen (z. B. `zeek/zeek:7.0`).
- Quelle/Kontext des Messdesigns: BA-Repo, `30_Ist-Analyse/` und `chat.md` (Abschnitt 11).
