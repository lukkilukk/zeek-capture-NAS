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
