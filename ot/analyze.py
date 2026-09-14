"""
The forensic "rewind" tool. After an incident (a pressure drop, a valve
in the wrong position, an unexplained outage), an engineer runs this to
answer the question OT networks normally can't answer: what write
command was sent, when, and from where?

Usage:
    python ot/analyze.py                  # show all write commands, most recent first
    python ot/analyze.py --coil 7         # narrow to a specific coil/register address
    python ot/analyze.py --since 60       # only commands from the last 60 seconds
"""
import sys
import os
import sqlite3
import time
import argparse

DB_PATH = "data/ot_blackbox.db"


def rewind(coil=None, since=None, db_path=DB_PATH, quiet=False):
    """Callable version, importable from ghostwatch.py or other code.
    Returns the list of matching rows (as sqlite3.Row objects).
    """
    if not os.path.exists(db_path):
        if not quiet:
            print(f"[!] {db_path} not found -- run ot/black_box.py first to capture some traffic.")
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM ot_events WHERE is_write = 1 AND direction = 'request'"
    params = []
    if coil is not None:
        query += " AND address = ?"
        params.append(coil)
    if since is not None:
        query += " AND timestamp >= ?"
        params.append(time.time() - since)
    query += " ORDER BY timestamp ASC"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    # De-duplicate by (transaction_id, src_port, address, value): on Linux,
    # sniffing the loopback interface ('lo') causes each packet to be
    # observed twice (a kernel/libpcap quirk specific to loopback, not
    # present on a real SPAN/mirror port capturing a physical link).
    seen = set()
    deduped = []
    for r in rows:
        key = (r["transaction_id"], r["src_port"], r["address"], r["value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    rows = deduped

    if not quiet:
        if not rows:
            print("[+] No write commands found matching that filter.")
        else:
            print(f"\n=== OT BLACK BOX REWIND: {len(rows)} write command(s) found ===\n")
            for r in rows:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["timestamp"]))
                print(
                    f"[{ts}] {r['function_name']:<22} "
                    f"source={r['src_ip']}:{r['src_port']:<6} -> plc={r['dst_ip']}:{r['dst_port']}  "
                    f"address={r['address']}  value={r['value']}"
                )
            print(
                "\nUse this timeline to correlate against the incident time and identify\n"
                "which source issued the command that caused it -- source_ip/port here\n"
                "stands in for the offending host on a real network."
            )

    return rows


def main():
    parser = argparse.ArgumentParser(description="Rewind the OT black box to find write commands.")
    parser.add_argument("--coil", type=int, default=None, help="Filter to a specific coil/register address")
    parser.add_argument("--since", type=float, default=None, help="Only show events in the last N seconds")
    args = parser.parse_args()
    rewind(coil=args.coil, since=args.since)


if __name__ == "__main__":
    main()
