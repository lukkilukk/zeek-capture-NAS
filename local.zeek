##! local.zeek - Zeek Passive Capture, Bachelorarbeit Kap. 3.3.1 (Ground Truth)
##!
##! Zweck: Kommunikationsmatrix des NAS 10.0.0.45 erheben, um die dokumentierte
##! Soll-Kommunikation des Condition-Monitoring-Stacks gegen den Ist-Verkehr zu
##! pruefen. Erzeugt ausschliesslich conn.log - kein pcap, keine Inhalte.
##!
##! Beobachtungspunkt: eth0 des NAS (Interface via CAPTURE_IFACE in Portainer).
##! Achtung: auf eth0 ist der containerinterne Verkehr (172.22.0.0/16,
##! Telegraf->InfluxDB, Grafana->InfluxDB) NICHT sichtbar - der laeuft ueber die
##! Docker-Bridge. Dafuer braucht es einen zweiten Lauf auf dem br-*-Interface.


# ---------------------------------------------------------------------------
# 1) Checksum Offloading
# ---------------------------------------------------------------------------
# Die NIC berechnet TCP-Pruefsummen erst in der Hardware. Im Mitschnitt stehen
# deshalb bei allen SELBST GESENDETEN Paketen ungueltige Pruefsummen. Zeek
# verwirft solche Pakete standardmaessig -> es saehe nur die Gegenrichtung.
#
# Symptom ohne diese Zeile: conn_state ist durchgehend SH / SHR / OTH,
# niemals SF. Byte-Zaehler und Richtungsangaben sind dann unbrauchbar.
#
# T = Pruefsummen ignorieren. Fuer eine reine Metadaten-Auswertung
# (wer spricht mit wem auf welchem Port) unbedenklich, weil die Pruefsumme
# nur die Nutzdaten-Integritaet betrifft, nicht die Header.
redef ignore_checksums = T;


# ---------------------------------------------------------------------------
# 2) Datensparsamkeit: nur conn.log
# ---------------------------------------------------------------------------
# Zeek aktiviert von Haus aus dutzende Protokoll-Analyzer, die eigene Logs
# schreiben - u.a. dns, http, ssl, files, x509, weird, dhcp, ntp, ssh, snmp,
# syslog, smtp. Mehrere davon sind datenschutzrechtlich heikel:
#   - dhcp.log  -> Hostnamen (im Werksnetz teils personenbezogen!)
#   - dns.log   -> aufgerufene Domains = Nutzungsverhalten
#   - http.log  -> URLs
#   - ssl.log   -> Server Names (SNI)
#
# Deshalb WHITELIST statt Blacklist: alles abschalten ausser den drei Streams,
# die gebraucht werden. Vorteil gegenueber einzelnen disable_stream-Zeilen:
# es greift auch bei Protokollen, die erst spaeter im Messzeitraum auftauchen
# und an die man beim Schreiben der Datei nicht gedacht hat.
#
# Behalten werden:
#   Conn::LOG          - die Kommunikationsmatrix, das eigentliche Messergebnis
#   Reporter::LOG      - Zeek-eigene Fehler/Warnungen (Nachweis Messqualitaet)
#   PacketFilter::LOG  - welcher BPF-Filter aktiv war (Reproduzierbarkeit)
#
# &priority=-10 sorgt dafuer, dass dieser Handler ALS LETZTER laeuft. Die
# einzelnen Protokollskripte legen ihre Streams selbst in zeek_init an - ohne
# die niedrige Prioritaet waeren manche davon noch gar nicht registriert.
#
# Die IDs werden erst gesammelt und dann abgeschaltet: Log::disable_stream()
# loescht intern aus Log::active_streams, und eine Tabelle darf nicht veraendert
# werden, waehrend man ueber sie iteriert.
#
# HINWEIS: Zeek gibt beim Start trotzdem mehrfach
#   "expression warning ... possible loop/iterator invalidation"
# aus. Das ist ein FALSCH-POSITIV der statischen Analyse - sie sieht nur, dass
# disable_stream() aus einer Schleife heraus gerufen wird, nicht, dass es eine
# andere Menge ist. Warnung, kein Fehler; Zeek laeuft normal weiter.
event zeek_init() &priority=-10
	{
	local to_disable: set[Log::ID];

	for ( id in Log::active_streams )
		if ( id != Conn::LOG &&
		     id != Reporter::LOG &&
		     id != PacketFilter::LOG )
			add to_disable[id];

	for ( id in to_disable )
		Log::disable_stream(id);
	}
