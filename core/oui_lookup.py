"""
Real MAC -> vendor lookup, using Scapy's bundled IEEE OUI database
(scapy.data.MANUFDB) -- the same database tools like Wireshark ship.
No network access or extra dependency required; works fully offline.

This turns a raw MAC like 'b8:27:eb:12:34:56' into 'Raspberry Pi Foundation',
'3c:22:fb:...' into 'Apple, Inc.', etc.
"""
from scapy.data import MANUFDB


def get_vendor(mac):
    """Return the full vendor name for a MAC address, or 'Unknown' if the
    OUI isn't in the database (e.g. randomized/locally-administered MACs,
    which is common for modern phones doing MAC randomization -- that's
    itself a useful signal, not a bug).
    """
    if not mac:
        return "Unknown"
    try:
        vendor = MANUFDB._get_manuf(mac)
    except Exception:
        return "Unknown"

    if not vendor or vendor == mac:
        # scapy returns the MAC itself back when it has no match
        return "Unknown"
    return vendor


def is_locally_administered(mac):
    """A MAC with the locally-administered bit set (2nd bit of the first
    octet) is not tied to a real manufacturer -- typically MAC
    randomization (iOS/Android privacy features) or a virtual NIC.
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0b00000010)
    except Exception:
        return False
