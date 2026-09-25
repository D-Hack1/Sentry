# ===========================================================================
# zeek/scripts/ike.zeek
# AI-Powered IPsec VPN Protocol Analyzer - SIH 2026
# IKE Protocol Metadata Logger (Aadi - ML)
#
# Logs plaintext IKE exchange metadata to ike.log:
# ts, id.orig_h, id.resp_h, id.orig_p, id.resp_p, version, exchange_type,
# spi_i, spi_r, flags, msg_id
# ===========================================================================

module IKE_Analyzer;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:            time   &log;
        orig_h:        addr   &log;
        resp_h:        addr   &log;
        orig_p:        port   &log;
        resp_p:        port   &log;
        version:       count  &log;
        exchange_type: count  &log;
        spi_i:         string &log;
        spi_r:         string &log;
        flags:         count  &log;
        msg_id:        count  &log;
    };
}

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="ike"]);
}

# Generic UDP packet analyzer fallback for IKE (ports 500 and 4500)
event udp_contents(u: connection, is_orig: bool, contents: string) {
    if ( u$id$orig_p != 500/udp && u$id$resp_p != 500/udp &&
         u$id$orig_p != 4500/udp && u$id$resp_p != 4500/udp )
        return;

    local data = contents;
    # Skip NAT-T non-ESP 4-byte zero marker if present
    if ( |data| >= 32 && sub_bytes(data, 1, 4) == "\x00\x00\x00\x00" ) {
        data = sub_bytes(data, 5, |data| - 4);
    }

    if ( |data| < 28 )
        return;

    # Extract IKE header fields
    local spi_i_raw = sub_bytes(data, 1, 8);
    local spi_r_raw = sub_bytes(data, 9, 8);
    local next_payload = bytestring_to_count(sub_bytes(data, 17, 1));
    local ver_byte = bytestring_to_count(sub_bytes(data, 18, 1));
    local version = (ver_byte >> 4) & 0x0F;
    local exch_type = bytestring_to_count(sub_bytes(data, 19, 1));
    local flags = bytestring_to_count(sub_bytes(data, 20, 1));
    local msg_id = bytestring_to_count(sub_bytes(data, 21, 4));

    local rec: Info = [
        $ts            = network_time(),
        $orig_h        = u$id$orig_h,
        $resp_h        = u$id$resp_h,
        $orig_p        = u$id$orig_p,
        $resp_p        = u$id$resp_p,
        $version       = version,
        $exchange_type = exch_type,
        $spi_i         = fmt("0x%s", hex_encode(spi_i_raw)),
        $spi_r         = fmt("0x%s", hex_encode(spi_r_raw)),
        $flags         = flags,
        $msg_id        = msg_id
    ];

    Log::write(LOG, rec);
}
