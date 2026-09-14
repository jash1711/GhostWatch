"""
Prints a terminal snapshot of current asset states and all alerts raised
so far. Useful for quick checks without spinning up the dashboard.

Usage:
    python cli/status.py [config.yaml]
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
from core.db import get_conn


def print_status(config_path="config.yaml"):
    """Callable version, importable from ghostwatch.py or other code."""
    with open(config_path) as f:
        config = yaml.safe_load(f)
    conn = get_conn(config["db_path"])

    print("\n=== ASSETS ===")
    rows = conn.execute(
        "SELECT mac, state, vendor_full, ja3_label, ips, hostnames, first_seen, last_seen "
        "FROM assets ORDER BY last_seen DESC"
    ).fetchall()
    if not rows:
        print("(none yet -- run the sensor or replay mode first)")
    for r in rows:
        vendor = r["vendor_full"] or "Unknown"
        ja3 = r["ja3_label"] or ""
        ja3_str = f" ja3={ja3}" if ja3 else ""
        print(f"{r['mac']:<20} state={r['state']:<13} vendor={vendor:<26} "
              f"ips={r['ips']:<24}{ja3_str}")

    print("\n=== ALERTS ===")
    alerts = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC").fetchall()
    if not alerts:
        print("(none)")
    for a in alerts:
        print(f"[{a['severity']:<8}] {a['alert_type']:<32} mac={a['mac']:<20} ip={a['ip']:<15} - {a['detail']}")

    conn.close()


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    print_status(config_path)


if __name__ == "__main__":
    main()
