"""
Marks an asset as Decommissioned. In a real deployment this would be
triggered automatically by an ITSM/CMDB webhook (ServiceNow, Jira,
etc.) -- here it's a manual CLI to simulate that feed.

Usage:
    python cli/decommission.py <MAC_ADDRESS> [config.yaml]
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
from core.db import get_conn
from core.state_engine import StateEngine


def decommission(mac, config_path="config.yaml"):
    """Callable version, importable from ghostwatch.py or other code."""
    with open(config_path) as f:
        config = yaml.safe_load(f)
    conn = get_conn(config["db_path"])
    engine = StateEngine(conn, config)
    ok = engine.mark_decommissioned(mac)
    conn.close()
    return ok


def main():
    if len(sys.argv) < 2:
        print("Usage: python cli/decommission.py <MAC_ADDRESS> [config.yaml]")
        sys.exit(1)
    mac = sys.argv[1]
    config_path = sys.argv[2] if len(sys.argv) > 2 else "config.yaml"

    ok = decommission(mac, config_path)
    if ok:
        print(f"[+] Asset {mac} marked as Decommissioned.")
    else:
        print(f"[!] Asset {mac} not found in database. Has the sensor seen it yet?")


if __name__ == "__main__":
    main()
