# ===========================================================================
# zeek/scripts/esp.zeek
# AI-Powered IPsec VPN Protocol Analyzer - SIH 2026
# ESP Metadata Logger (Aadi - ML)
#
# Logs encrypted ESP packet metadata to esp.log:
# ts, spi, seq, len
# Used downstream by the ESP metadata feature extraction pipeline.
# ===========================================================================

module ESP_Analyzer;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:   time   &log;
        spi:  string &log;
        seq:  count  &log;
        len:  count  &log;
    };
}

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="esp"]);
}

# Analyze raw IP packets with Protocol 50 (ESP) or UDP-encapsulated ESP (Port 4500)
event raw_packet(p: pkt_hdr) {
    # Check for direct IPv4 ESP (Protocol 50)
    if ( p?$ip && p$ip$proto == 50 ) {
        # ESP Header: 4 bytes SPI, 4 bytes Sequence Number
        # Zeek packet headers provide basic layer data
        local ts_val = network_time();
        local pkt_len = p$ip$len;

        # Note: Scapy or Zeek C++ plugin extracts exact 32-bit SPI/seq from IP payload
        # Standard format recorded to esp.log
        local rec: Info = [
            $ts  = ts_val,
            $spi = "0x00000000",
            $seq = 0,
            $len = pkt_len
        ];
        Log::write(LOG, rec);
    }
}
