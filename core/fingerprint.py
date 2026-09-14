"""
Extracts a lightweight fingerprint from a single packet.

MAC, IP, event type (ARP / TCP_SYN / DHCP / TLS_CLIENT_HELLO / generic IP
traffic), destination port for SYNs, DHCP hostname if offered, a real IEEE
vendor name for the MAC (via core.oui_lookup), and a JA3 TLS fingerprint
when the packet is a TLS ClientHello (via core.ja3).
"""
from scapy.all import Ether, IP, TCP, ARP, DHCP, Raw
from core.oui_lookup import get_vendor
from core.ja3 import compute_ja3


def extract_fingerprint(pkt):
    if not pkt.haslayer(Ether):
        return None

    result = {"mac": pkt[Ether].src}
    result["vendor"] = get_vendor(result["mac"])

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        result["ip"] = arp.psrc
        result["event_type"] = "ARP"
        return result

    if pkt.haslayer(IP):
        result["ip"] = pkt[IP].src

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]

        # Check for a TLS ClientHello before the generic SYN check -- a
        # ClientHello rides on an established connection (ACK+PSH set, not
        # a bare SYN) and carries far more fingerprinting value than a port.
        if pkt.haslayer(Raw):
            raw_bytes = bytes(pkt[Raw].load)
            ja3_result = compute_ja3(raw_bytes)
            if ja3_result is not None:
                ja3_string, ja3_hash, ja3_label = ja3_result
                result["event_type"] = "TLS_CLIENT_HELLO"
                result["port"] = int(tcp.dport)
                result["ja3_hash"] = ja3_hash
                result["ja3_label"] = ja3_label
                return result

        if int(tcp.flags) & 0x02:  # SYN flag set
            result["event_type"] = "TCP_SYN"
            result["port"] = int(tcp.dport)
            return result

    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "hostname":
                val = opt[1]
                result["hostname"] = val.decode() if isinstance(val, bytes) else val
        result["event_type"] = "DHCP"
        return result

    if "ip" in result:
        result["event_type"] = "IP_TRAFFIC"
        return result

    return None
