"""
Live passive capture mode.

Must be run with root/administrator privileges, on an interface that sees
the traffic you care about: a switch SPAN/mirror port, a network tap, or
(for local testing only) your own host's interface.

This does NOT actively probe or scan -- it only listens. That passivity
is the point: it works even against devices that would never respond to
a credentialed scan (decommissioned hardware, OT devices, anything
air-gapped from the management network).

Usage:
    sudo python sensor/capture.py <interface> [config.yaml]

Example:
    sudo python sensor/capture.py eth0
    sudo python sensor/capture.py "Wi-Fi"
"""
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
from scapy.all import sniff
from core.fingerprint import extract_fingerprint
from core.state_engine import StateEngine
from core.detector import Detector
from core.db import get_conn


def main(interface, config_path="config.yaml"):
    with open(config_path) as f:
        config = yaml.safe_load(f)

    conn = get_conn(config["db_path"])
    engine = StateEngine(conn, config)
    detector = Detector(conn, config)

    state = {"last_age_sweep": time.time()}
    age_sweep_interval = 30  # seconds

    def handle(pkt):
        fp = extract_fingerprint(pkt)
        if fp and "mac" in fp:
            mac = fp["mac"]
            ip = fp.get("ip")
            transition = engine.process_event(
                mac, ip, fp.get("event_type", "UNKNOWN"),
                port=fp.get("port"), hostname=fp.get("hostname"),
                vendor=fp.get("vendor"), ja3_hash=fp.get("ja3_hash"),
                ja3_label=fp.get("ja3_label"),
            )
            detector.evaluate_transition(mac, ip, transition)
            if fp.get("port"):
                row = conn.execute("SELECT state FROM assets WHERE mac=?", (mac,)).fetchone()
                if row:
                    detector.evaluate_port_event(mac, ip, row["state"], fp["port"])

        if time.time() - state["last_age_sweep"] > age_sweep_interval:
            engine.age_assets()
            state["last_age_sweep"] = time.time()

    print(f"[+] GhostWatch sensor listening on '{interface}' (Ctrl+C to stop)...")
    sniff(iface=interface, prn=handle, store=False)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python sensor/capture.py <interface> [config.yaml]")
        sys.exit(1)
    iface = sys.argv[1]
    cfg = sys.argv[2] if len(sys.argv) > 2 else "config.yaml"
    main(iface, cfg)
