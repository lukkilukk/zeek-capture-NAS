# zeek-capture-NAS

Kurzlebiger **Zeek Passive Capture**-Stack fuer die Ground-Truth-Messung der
Bachelorarbeit (Kap. 3.3.1). Laeuft in Portainer **neben** dem Condition-Monitoring-
Stack, ohne ihn anzufassen. Erzeugt nur `conn.log` (Kommunikationsmatrix) --
kein pcap, keine Inhalts-/Domain-Logs (Datenschutz, Kap. 3.5).

## Deploy in Portainer (exakte Felder)

**Vorher in DSM File Station:** Ordner `/volume1/docker/zeek-capture/logs` anlegen,
Rechte auf Lesen/Schreiben setzen.

Portainer -> Stacks -> Add stack -> **Repository**:

| Feld | Wert |
|---|---|
| Build method | Repository |
| Repository URL | `https://github.com/lukkilukk/zeek-capture-NAS.git` |
| Reference | `refs/heads/main` |
| Compose path | `docker-compose.yml` |
| Environment (optional) | `CAPTURE_IFACE` (Default `any`) |

Dann **Deploy**. Nach kuenftigen Pushes: **Pull and redeploy**.

> Privates Repo -> Portainer braucht GitHub-Login/PAT zum Klonen.
> Alternativ das Repo auf **Public** stellen (es enthaelt keine Secrets) -> kein Token noetig.

## Laufzeit
Live laufen lassen bis Saettigung (2-3 Tage keine neuen Kommunikationspaare).

## Auswerten (am PC, ohne Konsole)
`conn.log` liegt im Netzwerkordner unter `docker/zeek-capture/logs/`. Herunterladen;
es ist eine Tab-getrennte TSV mit u. a. `id.orig_h` (Quelle), `id.resp_h` (Ziel),
`id.resp_p` (Zielport), `service`. Nach (Quelle, Ziel, Zielport) gruppieren
-> Kommunikationsmatrix -> gegen die dokumentierte Soll-Kommunikation abgleichen.

## Aufraeumen
Stack in Portainer loeschen -- der CM-Stack bleibt unberuehrt. Logs im
Netzwerkordner bleiben, bis manuell geloescht.

## Hinweise
- `network_mode: host` + `NET_RAW`/`NET_ADMIN` sind zum Mitlesen noetig.
- Fuer die dokumentierte Endfassung Image-Version pinnen (z. B. `zeek/zeek:7.0`).
- Kontext des Messdesigns: BA-Repo `30_Ist-Analyse/` und `chat.md` (Abschnitt 11).
