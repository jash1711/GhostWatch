#!/usr/bin/env python3
"""
GhostWatch -- single entrypoint for the whole tool.

Every capability (passive lifecycle sensor, decommission/status, dashboard,
the OT/Modbus black-box demo, OUI vendor lookup) is reachable from this one
file, so you don't need to remember which script lives where.

Examples:
    python ghostwatch.py replay data/initial_traffic.pcap
    python ghostwatch.py live eth0
    python ghostwatch.py decommission de:ad:be:ef:00:99
    python ghostwatch.py status
    python ghostwatch.py dashboard
    python ghostwatch.py gen-test-traffic
    python ghostwatch.py ot-demo --port 5030
    python ghostwatch.py vendor b8:27:eb:12:34:56
    python ghostwatch.py siem-info
"""
import argparse
import os
import platform
import subprocess
import sys
import threading
import time

# Make sure imports work regardless of the caller's working directory,
# as long as this file stays at the project root.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)


def cmd_replay(args):
    from sensor.replay import replay
    replay(args.pcap, args.config)


def cmd_live(args):
    from sensor.capture import main as capture_main
    capture_main(args.interface, args.config)


def cmd_decommission(args):
    from cli.decommission import decommission
    ok = decommission(args.mac, args.config)
    if ok:
        print(f"[+] Asset {args.mac} marked as Decommissioned.")
    else:
        print(f"[!] Asset {args.mac} not found in database. Has the sensor seen it yet?")


def cmd_status(args):
    from cli.status import print_status
    print_status(args.config)


def cmd_dashboard(args):
    print("[+] Launching Streamlit dashboard (Ctrl+C to stop)...")
    subprocess.run(["streamlit", "run", os.path.join(PROJECT_ROOT, "dashboard", "app.py")])


def cmd_gen_test_traffic(args):
    from scripts.gen_test_traffic import build
    build()


def cmd_gen_ot_incident(args):
    from scripts.gen_ot_incident_pcap import build
    build()


def cmd_vendor(args):
    from core.oui_lookup import get_vendor, is_locally_administered
    vendor = get_vendor(args.mac)
    locally_admin = is_locally_administered(args.mac)
    print(f"MAC:                {args.mac}")
    print(f"Vendor:             {vendor}")
    print(f"Locally administered (randomized/virtual): {locally_admin}")


def cmd_list_interfaces(args):
    """Lists network interface names as Scapy sees them -- the exact
    strings needed for `live` and `ot-demo --iface`. Interface naming is
    the single most common cross-platform gotcha (Linux uses short names
    like 'eth0'/'lo'; Windows uses long Npcap names like
    'Loopback Pseudo-Interface 1' or 'Ethernet').
    """
    try:
        from scapy.all import show_interfaces
        show_interfaces()
    except Exception:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            print(iface)


def default_loopback_iface():
    """Best-guess loopback interface name for the OT demo's default.
    Linux/macOS: 'lo'. Windows (via Npcap): 'Loopback Pseudo-Interface 1'.
    Always overridable with --iface if your system differs -- run
    `python ghostwatch.py list-interfaces` to find the exact name.
    """
    return "Loopback Pseudo-Interface 1" if platform.system() == "Windows" else "lo"


def cmd_siem_info(args):
    print(f"CEF alerts file:   {os.path.join(PROJECT_ROOT, 'data', 'alerts.cef')}")
    print(f"JSON Lines file:   {os.path.join(PROJECT_ROOT, 'data', 'alerts.jsonl')}")
    print("Both files are appended to automatically every time GhostWatch")
    print("raises an alert (from replay, live capture, or the OT demo).")
    print()
    for path in ("data/alerts.cef", "data/alerts.jsonl"):
        if os.path.exists(path):
            with open(path) as f:
                lines = f.readlines()
            print(f"--- last 3 lines of {path} ({len(lines)} total) ---")
            for line in lines[-3:]:
                print(line.rstrip())
            print()
        else:
            print(f"(no {path} yet -- raise some alerts first)")


def cmd_ot_replay(args):
    """Feeds a .pcap file from a past incident through the same Modbus
    parser the live recorder uses -- for when GhostWatch wasn't running
    at the time, but someone captured the traffic another way.
    """
    from ot.replay import replay
    replay(args.pcap, args.port)


def cmd_ot_rewind(args):
    """Queries the existing OT black-box database directly -- for
    investigating something already captured (live or replayed) without
    spinning up a new demo scenario.
    """
    from ot.analyze import rewind
    rewind(coil=args.coil, since=args.since)


def cmd_ot_live(args):
    """Continuous, unattended OT black-box recording against a real
    Modbus network -- no simulated PLC, no synthetic traffic, just
    listening indefinitely until stopped. This is the real-deployment
    counterpart to `ot-demo`.
    """
    from ot.black_box import main as blackbox_main
    print(f"[+] Recording live Modbus TCP traffic on '{args.iface}' (port {args.port}). Ctrl+C to stop.")
    blackbox_main(args.iface, args.port, duration=None)


def cmd_ot_demo(args):
    """Runs the full OT black-box scenario in ONE process using threads:
    simulated PLC, passive recorder, legit traffic, attacker traffic, then
    the forensic rewind -- no shell scripting, no cross-environment issues.
    """
    from ot.modbus_server import main as modbus_main
    from ot.black_box import main as blackbox_main
    from ot.legit_client import main as legit_main
    from ot.attacker_client import main as attacker_main
    from ot.analyze import rewind

    port = args.port
    iface = args.iface or default_loopback_iface()
    duration = args.duration

    print(f"=== 1. Starting simulated PLC on port {port} ===")
    server_thread = threading.Thread(target=modbus_main, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(1.5)

    print(f"\n=== 2. Starting OT black-box recorder on '{iface}' (runs for {duration}s) ===")
    capture_failed = threading.Event()

    def _safe_blackbox_run():
        try:
            blackbox_main(iface, port, duration)
        except Exception as e:
            capture_failed.set()
            print(f"\n[!] OT black-box recorder failed to start on interface '{iface}': {e}")
            print("[!] Interface names vary by OS -- run `python ghostwatch.py list-interfaces` "
                  "to see the exact names Scapy sees on this machine, then pass e.g. "
                  "`--iface \"Loopback Pseudo-Interface 1\"` (Windows) or `--iface lo` (Linux/macOS).")

    capture_thread = threading.Thread(target=_safe_blackbox_run, daemon=True)
    capture_thread.start()
    time.sleep(1.0)

    if capture_failed.is_set():
        print("\n[!] Aborting demo -- fix the interface name above and re-run.")
        return

    print("\n=== 3. LEGITIMATE HMI traffic (routine polling + authorized valve close on coil 2) ===")
    legit_main(port)
    time.sleep(1.0)

    print("\n=== 4. ATTACKER traffic (unauthorized write to coil 7 - Norwegian dam scenario) ===")
    attacker_main(port)

    print(f"\n=== 5. Waiting for capture window to close (up to {duration}s) ===")
    capture_thread.join(timeout=duration + 5)

    print("\n=== 6. FORENSIC REWIND ===")
    rewind()


def main():
    parser = argparse.ArgumentParser(
        prog="ghostwatch",
        description="GhostWatch -- lifecycle-aware, passive asset sentinel with OT forensic recorder.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("replay", help="Replay a pcap file through the detection pipeline")
    p.add_argument("pcap")
    p.add_argument("--config", default="config.yaml")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("live", help="Live passive capture on a network interface (needs root/admin)")
    p.add_argument("interface")
    p.add_argument("--config", default="config.yaml")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("decommission", help="Mark an asset as Decommissioned")
    p.add_argument("mac")
    p.add_argument("--config", default="config.yaml")
    p.set_defaults(func=cmd_decommission)

    p = sub.add_parser("status", help="Print current assets and alerts")
    p.add_argument("--config", default="config.yaml")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("dashboard", help="Launch the Streamlit dashboard")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("gen-test-traffic", help="Generate synthetic pcaps for testing/demoing")
    p.set_defaults(func=cmd_gen_test_traffic)

    p = sub.add_parser("gen-ot-incident", help="Generate a synthetic past-incident pcap for ot-replay")
    p.set_defaults(func=cmd_gen_ot_incident)

    p = sub.add_parser("vendor", help="Look up the real IEEE vendor for a MAC address")
    p.add_argument("mac")
    p.set_defaults(func=cmd_vendor)

    p = sub.add_parser("list-interfaces", help="List network interface names as Scapy sees them")
    p.set_defaults(func=cmd_list_interfaces)

    p = sub.add_parser("siem-info", help="Show where CEF/JSON SIEM export files live and their tail")
    p.set_defaults(func=cmd_siem_info)

    p = sub.add_parser("ot-demo", help="Run the full OT/Modbus black-box scenario in one process")
    p.add_argument("--port", type=int, default=5030)
    p.add_argument("--iface", default=None,
                    help="Loopback interface name. Auto-detected per OS if omitted "
                         "('lo' on Linux/macOS, 'Loopback Pseudo-Interface 1' on Windows). "
                         "Run list-interfaces if the auto-detected name doesn't match your system.")
    p.add_argument("--duration", type=int, default=8, help="Capture window in seconds")
    p.set_defaults(func=cmd_ot_demo)

    p = sub.add_parser("ot-live", help="Continuous OT black-box recording on a real network (needs root/admin)")
    p.add_argument("iface", help="Real network interface, e.g. eth0 or \"Ethernet\"")
    p.add_argument("--port", type=int, default=502, help="Modbus TCP port (default: 502, the real one)")
    p.set_defaults(func=cmd_ot_live)

    p = sub.add_parser("ot-replay", help="Replay a past-incident .pcap through the OT black-box parser")
    p.add_argument("pcap")
    p.add_argument("--port", type=int, default=502, help="Modbus TCP port to match in the pcap (default: 502)")
    p.set_defaults(func=cmd_ot_replay)

    p = sub.add_parser("ot-rewind", help="Query the existing OT black-box database (no new capture)")
    p.add_argument("--coil", type=int, default=None, help="Filter to a specific coil/register address")
    p.add_argument("--since", type=float, default=None, help="Only show events in the last N seconds")
    p.set_defaults(func=cmd_ot_rewind)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
