"""
The OT "black box" -- a lightweight forensic flight recorder for Modbus
TCP traffic.

Passively sniffs traffic on the wire and decodes real Modbus TCP frames
(MBAP header + PDU) directly from the packet bytes -- no external Modbus
dissector library needed. It records METADATA only (who, when, which
function code, which coil/register, what value) rather than full
payloads, matching the "record metadata not payloads" design from the
project brief: enough to reconstruct what happened, without the storage
or privacy cost of full packet capture.

Findings are kept in a bounded ring buffer (oldest rows are dropped once
MAX_ROWS is exceeded) -- this is the metadata equivalent of the circular
pcap buffer described in the brief.

Usage:
    sudo python ot/black_box.py <interface> [port]

Example (Linux, testing against the local simulator):
    sudo python ot/black_box.py lo 5020

Example (Windows, real network, real Modbus port):
    python ot/black_box.py "Ethernet" 502
"""
import sys
import os
import sqlite3
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff, TCP, IP, Raw

DB_PATH = "data/ot_blackbox.db"
MAX_ROWS = 5000  # ring buffer cap -- oldest rows are dropped beyond this

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}

# Function codes that represent a WRITE (a command that changes physical
# state -- opening a valve, energizing a relay) rather than a read/poll.
WRITE_FUNCTION_CODES = {5, 6, 15, 16}


def init_db(db_path):
    dirpath = os.path.dirname(db_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            direction TEXT,        -- 'request' or 'response'
            transaction_id INTEGER,
            unit_id INTEGER,
            function_code INTEGER,
            function_name TEXT,
            is_write INTEGER,
            address INTEGER,
            value INTEGER
        )
    """)
    conn.commit()
    return conn


def parse_modbus_frame(payload):
    """Parse an MBAP header + PDU from raw Modbus TCP bytes.
    Returns a dict of decoded fields, or None if this isn't a well-formed
    Modbus TCP frame.
    """
    if len(payload) < 8:
        return None

    transaction_id = int.from_bytes(payload[0:2], "big")
    protocol_id = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    unit_id = payload[6]
    function_code = payload[7]

    if protocol_id != 0:
        return None  # not Modbus (protocol id must be 0)

    result = {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "function_name": FUNCTION_NAMES.get(function_code, f"Unknown(0x{function_code:02x})"),
        "is_write": function_code in WRITE_FUNCTION_CODES,
        "address": None,
        "value": None,
    }

    data = payload[8:]
    if function_code == 5 and len(data) >= 4:  # Write Single Coil
        result["address"] = int.from_bytes(data[0:2], "big")
        raw_val = int.from_bytes(data[2:4], "big")
        result["value"] = 1 if raw_val == 0xFF00 else 0
    elif function_code == 6 and len(data) >= 4:  # Write Single Register
        result["address"] = int.from_bytes(data[0:2], "big")
        result["value"] = int.from_bytes(data[2:4], "big")
    elif function_code in (1, 2, 3, 4) and len(data) >= 4:  # reads
        result["address"] = int.from_bytes(data[0:2], "big")
        result["value"] = int.from_bytes(data[2:4], "big")  # quantity requested

    return result


def enforce_ring_buffer(conn):
    count = conn.execute("SELECT COUNT(*) FROM ot_events").fetchone()[0]
    if count > MAX_ROWS:
        excess = count - MAX_ROWS
        conn.execute(
            "DELETE FROM ot_events WHERE id IN "
            "(SELECT id FROM ot_events ORDER BY id ASC LIMIT ?)",
            (excess,),
        )
        conn.commit()


def main(interface, modbus_port=5020, duration=None):
    conn = init_db(DB_PATH)
    print(f"[+] OT black-box recorder listening on '{interface}' for Modbus TCP (port {modbus_port})")
    print(f"[+] Writing metadata-only records to {DB_PATH} (ring buffer cap: {MAX_ROWS} rows)")

    def handle(pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw)):
            return
        tcp = pkt[TCP]
        if tcp.sport != modbus_port and tcp.dport != modbus_port:
            return

        payload = bytes(pkt[Raw].load)
        parsed = parse_modbus_frame(payload)
        if parsed is None:
            return

        direction = "request" if tcp.dport == modbus_port else "response"

        conn.execute(
            "INSERT INTO ot_events (timestamp, src_ip, src_port, dst_ip, dst_port, direction, "
            "transaction_id, unit_id, function_code, function_name, is_write, address, value) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                time.time(), pkt[IP].src, tcp.sport, pkt[IP].dst, tcp.dport, direction,
                parsed["transaction_id"], parsed["unit_id"], parsed["function_code"],
                parsed["function_name"], int(parsed["is_write"]), parsed["address"], parsed["value"],
            ),
        )
        conn.commit()
        enforce_ring_buffer(conn)

        if parsed["is_write"] and direction == "request":
            print(f"[WRITE] {pkt[IP].src}:{tcp.sport} -> {pkt[IP].dst}:{tcp.dport}  "
                  f"{parsed['function_name']}  address={parsed['address']} value={parsed['value']}")

    sniff(iface=interface, prn=handle, store=False, timeout=duration)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python ot/black_box.py <interface> [modbus_port]")
        sys.exit(1)
    iface = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5020
    main(iface, port)
