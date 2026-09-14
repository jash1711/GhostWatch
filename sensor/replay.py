"""
Replay mode: feeds a .pcap file through the exact same fingerprint ->
state engine -> detector pipeline that live capture uses.

This is a real, useful mode on its own (analyzing a pcap pulled from a
switch mirror, or handed to you by an incident responder) -- not just a
test harness. It's also what lets you validate the whole pipeline without
needing raw-socket/root privileges or a live network tap.

Usage:
    python sensor/replay.py <pcap_file> [config.yaml]
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
from scapy.all import rdpcap
from core.fingerprint import extract_fingerprint
from core.state_engine import StateEngine
from core.detector import Detector
from core.db import get_conn


def replay(pcap_path, config_path="config.yaml"):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    conn = get_conn(config["db_path"])
    engine = StateEngine(conn, config)
    detector = Detector(conn, config)

    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} packets from {pcap_path}")

    processed = 0
    for pkt in packets:
        fp = extract_fingerprint(pkt)
        if fp is None or "mac" not in fp:
            continue
        mac = fp["mac"]
        ip = fp.get("ip")
        event_type = fp.get("event_type", "UNKNOWN")
        port = fp.get("port")
        hostname = fp.get("hostname")
        vendor = fp.get("vendor")
        ja3_hash = fp.get("ja3_hash")
        ja3_label = fp.get("ja3_label")

        transition = engine.process_event(
            mac, ip, event_type, port=port, hostname=hostname,
            vendor=vendor, ja3_hash=ja3_hash, ja3_label=ja3_label,
        )
        detector.evaluate_transition(mac, ip, transition)

        if port:
            row = conn.execute("SELECT state FROM assets WHERE mac=?", (mac,)).fetchone()
            if row:
                detector.evaluate_port_event(mac, ip, row["state"], port)

        processed += 1

    engine.age_assets()
    conn.close()
    print(f"[+] Processed {processed} relevant packets -> {config['db_path']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sensor/replay.py <pcap_file> [config.yaml]")
        sys.exit(1)
    pcap_file = sys.argv[1]
    cfg = sys.argv[2] if len(sys.argv) > 2 else "config.yaml"
    replay(pcap_file, cfg)
