"""
Offline OT replay: feeds a .pcap file (a capture handed to you after an
incident -- from a switch mirror, a tap, or a colleague's Wireshark
session) through the exact same Modbus parsing logic the live black-box
recorder uses.

This is what closes the gap live-only capture has: GhostWatch doesn't
need to have been running at the time of an incident, AS LONG AS someone
captured the raw traffic. Hand this the pcap and it reconstructs the
same metadata timeline `ot/analyze.py` reads from live capture.

Usage:
    python ot/replay.py <pcap_file> [modbus_port]

Then analyze it exactly as you would live-captured data:
    python ot/analyze.py
    python ot/analyze.py --coil 7
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import rdpcap, TCP, IP, Raw
from ot.black_box import init_db, parse_modbus_frame, enforce_ring_buffer, DB_PATH


def replay(pcap_path, modbus_port=502, db_path=DB_PATH):
    conn = init_db(db_path)
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} packets from {pcap_path}")

    matched = 0
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue
        tcp = pkt[TCP]
        if tcp.sport != modbus_port and tcp.dport != modbus_port:
            continue

        payload = bytes(pkt[Raw].load)
        parsed = parse_modbus_frame(payload)
        if parsed is None:
            continue

        direction = "request" if tcp.dport == modbus_port else "response"
        # pcap files carry real capture timestamps -- use them instead of
        # "now", so the forensic timeline reflects when the incident
        # actually happened, not when you happened to run the replay.
        ts = float(pkt.time)

        conn.execute(
            "INSERT INTO ot_events (timestamp, src_ip, src_port, dst_ip, dst_port, direction, "
            "transaction_id, unit_id, function_code, function_name, is_write, address, value) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ts, pkt[IP].src, tcp.sport, pkt[IP].dst, tcp.dport, direction,
                parsed["transaction_id"], parsed["unit_id"], parsed["function_code"],
                parsed["function_name"], int(parsed["is_write"]), parsed["address"], parsed["value"],
            ),
        )
        matched += 1
        if parsed["is_write"] and direction == "request":
            import time as _time
            ts_str = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(ts))
            print(f"[WRITE @ {ts_str}] {pkt[IP].src}:{tcp.sport} -> {pkt[IP].dst}:{tcp.dport}  "
                  f"{parsed['function_name']}  address={parsed['address']} value={parsed['value']}")

    conn.commit()
    enforce_ring_buffer(conn)
    conn.close()
    print(f"[+] Parsed {matched} Modbus frames -> {db_path}")
    print("[+] Run `python ot/analyze.py` (or `python ghostwatch.py ot-rewind`) to see the forensic timeline.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ot/replay.py <pcap_file> [modbus_port]")
        sys.exit(1)
    pcap_file = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    replay(pcap_file, port)
