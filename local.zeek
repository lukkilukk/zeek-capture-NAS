##! Ground-Truth-Capture fuer die Bachelorarbeit -- nur die Kommunikationsmatrix.
##!
##! Datenschutz/Datenminimierung (Kap. 3.5): KEIN pcap, bewusst KEINE inhalts-
##! oder domainhaltigen Logs. Behalten wird nur conn.log (Quelle, Ziel, Zielport,
##! Dienst, Dauer, Bytes) -- die Kommunikationsmatrix in Rohform.

event zeek_init()
{
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(Files::LOG);
    Log::disable_stream(X509::LOG);
    Log::disable_stream(Weird::LOG);
}


# NIC-Checksum-Offloading: Pruefsummen ignorieren, sonst verwirft Zeek
# alle vom NAS selbst gesendeten Pakete (conn_state SH/SHR statt SF).
redef ignore_checksums = T;

# Nur conn.log behalten - Whitelist statt Blacklist, damit auch
# ntp/ssh/snmp/syslog etc. gar nicht erst entstehen (Datensparsamkeit).
event zeek_init() &priority=-10
	{
	for ( id in Log::active_streams )
		if ( id != Conn::LOG && id != Reporter::LOG && id != PacketFilter::LOG )
			Log::disable_stream(id);
	}
