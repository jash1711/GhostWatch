"""
Generates synthetic pcap files that exercise the full GhostWatch pipeline
end to end, without needing a live network tap -- including a real IEEE
vendor match and a real, spec-valid TLS ClientHello for JA3 fingerprinting.

  data/initial_traffic.pcap      - 3 normal devices + 1 "ghost" device,
                                    all seen for the first time. One
                                    device also sends a TLS ClientHello.
  data/reactivation_traffic.pcap - the ghost device reappearing on RDP
                                    (port 3389) AFTER it has been marked
                                    Decommissioned via the CLI.

This is a legitimate feature in its own right (offline pipeline testing /
CI regression testing for the detector), not just a demo gimmick.

Usage:
    python scripts/gen_test_traffic.py
"""
import random
import struct
from scapy.all import Ether, IP, TCP, ARP, Raw, wrpcap

# A real Raspberry Pi Foundation OUI prefix (b8:27:eb) -- this is what lets
# the demo show a genuine, non-"Unknown" vendor lookup result, matching the
# "Raspberry Pi Foundation" example from the project brief.
GHOST_MAC = "b8:27:eb:00:00:99"
GHOST_IP = "192.168.1.99"


def make_arp(mac, ip):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst="192.168.1.1")


def make_syn(mac, ip, dport):
    return Ether(src=mac) / IP(src=ip, dst="192.168.1.50") / TCP(
        sport=random.randint(1024, 65535), dport=dport, flags="S"
    )


def build_tls_client_hello_bytes():
    """Builds a real, spec-valid TLS 1.2 ClientHello record (plaintext
    handshake bytes only -- no actual TLS session is established). Used to
    demonstrate JA3 fingerprint extraction in replay mode.
    """
    client_version = struct.pack("!H", 0x0303)
    random_bytes = bytes(random.randint(0, 255) for _ in range(32))
    session_id = b""
    session_id_len = struct.pack("!B", len(session_id))

    ciphers = [0xC02B, 0xC02F, 0x009C]  # a few common real cipher suite IDs
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_len = struct.pack("!H", len(cipher_bytes))

    compression = b"\x00"
    compression_len = struct.pack("!B", len(compression))

    curves = [0x001D, 0x0017]  # x25519, secp256r1
    curve_list = b"".join(struct.pack("!H", c) for c in curves)
    ext_curves = (
        struct.pack("!H", 10)
        + struct.pack("!H", len(curve_list) + 2)
        + struct.pack("!H", len(curve_list))
        + curve_list
    )

    point_formats = bytes([0x00])
    ext_points = (
        struct.pack("!H", 11)
        + struct.pack("!H", len(point_formats) + 1)
        + struct.pack("!B", len(point_formats))
        + point_formats
    )

    extensions = ext_curves + ext_points
    ext_len = struct.pack("!H", len(extensions))

    body = (
        client_version + random_bytes + session_id_len + session_id
        + cipher_len + cipher_bytes + compression_len + compression
        + ext_len + extensions
    )
    handshake_len = struct.pack("!I", len(body))[1:]  # 3-byte length field
    handshake = struct.pack("!B", 0x01) + handshake_len + body

    record = struct.pack("!B", 0x16) + struct.pack("!H", 0x0301) + struct.pack("!H", len(handshake)) + handshake
    return record


def make_tls_client_hello(mac, ip):
    return Ether(src=mac) / IP(src=ip, dst="192.168.1.50") / TCP(
        sport=random.randint(1024, 65535), dport=443, flags="PA", seq=1000
    ) / Raw(load=build_tls_client_hello_bytes())


def build():
    normal_devices = [
        ("aa:bb:cc:00:00:01", "192.168.1.10"),
        ("aa:bb:cc:00:00:02", "192.168.1.11"),
        ("aa:bb:cc:00:00:03", "192.168.1.12"),
    ]

    initial_packets = []
    for i, (mac, ip) in enumerate(normal_devices):
        initial_packets.append(make_arp(mac, ip))
        initial_packets.append(make_syn(mac, ip, 443))
        if i == 0:
            # one device also does a real TLS handshake, for JA3 testing
            initial_packets.append(make_tls_client_hello(mac, ip))

    # the ghost device is first seen here too, before it gets decommissioned
    initial_packets.append(make_arp(GHOST_MAC, GHOST_IP))
    initial_packets.append(make_syn(GHOST_MAC, GHOST_IP, 22))

    wrpcap("data/initial_traffic.pcap", initial_packets)

    # reactivation traffic: the ghost device comes back online AFTER being
    # marked Decommissioned (that step happens via the CLI, in between the
    # two replays). It also hits RDP -- a sensitive port -- making this a
    # realistic, high-signal detection.
    reactivation_packets = [
        make_arp(GHOST_MAC, GHOST_IP),
        make_syn(GHOST_MAC, GHOST_IP, 3389),
    ]
    wrpcap("data/reactivation_traffic.pcap", reactivation_packets)

    print("[+] Wrote data/initial_traffic.pcap and data/reactivation_traffic.pcap")
    print(f"[+] Ghost device MAC to decommission in the demo: {GHOST_MAC} (real Raspberry Pi OUI)")


if __name__ == "__main__":
    build()
