"""
JA3 fingerprinting (Salesforce's JA3 spec: https://github.com/salesforce/ja3).

JA3 fingerprints a TLS client by hashing together the fields it chooses
in its ClientHello: TLS version, offered cipher suites, extensions,
elliptic curves, and EC point formats. Two different applications
(a browser vs. curl vs. a custom IoT TLS stack) produce different,
consistent JA3 hashes even when connecting to the same server on the
same port -- so it gives a device/software fingerprint that port
numbers alone can't.

This parses the ClientHello directly from raw bytes. No external TLS
library is needed: we only need to read plaintext handshake fields
that are sent before any encryption begins.
"""
import hashlib
import struct

# GREASE values (RFC 8701) are reserved values some clients (mainly Chrome)
# insert to prevent protocol ossification. JA3 explicitly excludes them.
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# A small illustrative set of known JA3 hashes -> human labels.
# This is NOT a comprehensive database (a real deployment would pull from
# a maintained JA3 fingerprint feed) -- it's enough to demonstrate the
# mechanism and label a few extremely common clients.
KNOWN_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Python requests/urllib3 (older)",
    "cd08e31494f9531f560d64c695473da9": "curl (generic, common default)",
}


def _read_u8(data, offset):
    return data[offset], offset + 1


def _read_u16(data, offset):
    return struct.unpack("!H", data[offset:offset + 2])[0], offset + 2


def _read_u24(data, offset):
    return int.from_bytes(data[offset:offset + 3], "big"), offset + 3


def parse_client_hello(payload):
    """Parse a single (unfragmented) TLS record containing a ClientHello.
    Returns a dict of decoded fields, or None if this isn't a recognizable
    ClientHello.
    """
    if len(payload) < 6:
        return None

    content_type = payload[0]
    if content_type != 0x16:  # not a TLS Handshake record
        return None

    try:
        record_version, offset = _read_u16(payload, 1)
        record_length, offset = _read_u16(payload, 3)

        handshake_type, offset = _read_u8(payload, offset)
        if handshake_type != 0x01:  # not a ClientHello
            return None
        handshake_length, offset = _read_u24(payload, offset)

        client_version, offset = _read_u16(payload, offset)
        offset += 32  # skip 32-byte random

        session_id_len, offset = _read_u8(payload, offset)
        offset += session_id_len

        cipher_suites_len, offset = _read_u16(payload, offset)
        n_ciphers = cipher_suites_len // 2
        ciphers = []
        for _ in range(n_ciphers):
            c, offset = _read_u16(payload, offset)
            if c not in GREASE_VALUES:
                ciphers.append(c)

        compression_len, offset = _read_u8(payload, offset)
        offset += compression_len

        extensions = []
        curves = []
        point_formats = []

        if offset < len(payload):
            extensions_len, offset = _read_u16(payload, offset)
            ext_end = offset + extensions_len
            while offset < ext_end:
                ext_type, offset = _read_u16(payload, offset)
                ext_len, offset = _read_u16(payload, offset)
                ext_data_start = offset

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                if ext_type == 10:  # supported_groups (elliptic curves)
                    list_len, list_offset = _read_u16(payload, ext_data_start)
                    n_curves = list_len // 2
                    for i in range(n_curves):
                        curve, list_offset = _read_u16(payload, list_offset)
                        if curve not in GREASE_VALUES:
                            curves.append(curve)
                elif ext_type == 11:  # ec_point_formats
                    fmt_len, fmt_offset = _read_u8(payload, ext_data_start)
                    for i in range(fmt_len):
                        pf, fmt_offset = _read_u8(payload, fmt_offset)
                        point_formats.append(pf)

                offset = ext_data_start + ext_len

        return {
            "version": client_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "curves": curves,
            "point_formats": point_formats,
        }
    except (IndexError, struct.error):
        # Truncated/fragmented ClientHello (spans multiple TCP segments) --
        # not fatal, just means we skip fingerprinting this one connection.
        return None


def compute_ja3(payload):
    """Given raw TLS record bytes containing a ClientHello, return
    (ja3_string, ja3_hash, label). label is a human-readable guess from
    KNOWN_JA3, or None if not recognized.
    """
    fields = parse_client_hello(payload)
    if fields is None:
        return None

    ja3_string = "{},{},{},{},{}".format(
        fields["version"],
        "-".join(str(c) for c in fields["ciphers"]),
        "-".join(str(e) for e in fields["extensions"]),
        "-".join(str(c) for c in fields["curves"]),
        "-".join(str(p) for p in fields["point_formats"]),
    )
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
    label = KNOWN_JA3.get(ja3_hash)
    return ja3_string, ja3_hash, label
