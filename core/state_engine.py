"""
The core innovation: a lifecycle state machine per asset.

States: New -> Active -> Idle -> Orphaned -> Decommissioned (manual)
Special state: Reactivated - set when a Decommissioned asset is seen again.
This is never silently folded back into "Active": a reactivation is always
a notable, alert-worthy event, because it means something that was
supposed to be dead and buried is talking on the network again.
"""
import time
import json


class StateEngine:
    def __init__(self, conn, config):
        self.conn = conn
        self.config = config

    def _get_asset(self, mac):
        cur = self.conn.execute("SELECT * FROM assets WHERE mac = ?", (mac,))
        return cur.fetchone()

    def _log_history(self, mac, state, evidence):
        self.conn.execute(
            "INSERT INTO state_history (mac, state, timestamp, evidence) VALUES (?, ?, ?, ?)",
            (mac, state, time.time(), evidence),
        )

    def process_event(self, mac, ip, event_type, port=None, hostname=None,
                       vendor=None, ja3_hash=None, ja3_label=None):
        """Feed one observed event into the state machine.
        Returns (from_state, to_state) if a notable transition occurred, else None.
        """
        now = time.time()
        asset = self._get_asset(mac)

        self.conn.execute(
            "INSERT INTO events (mac, ip, event_type, port, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (mac, ip, event_type, port, now, f"{event_type} observed"),
        )

        transition = None

        if asset is None:
            ips = json.dumps([ip] if ip else [])
            hostnames = json.dumps([hostname] if hostname else [])
            self.conn.execute(
                "INSERT INTO assets (mac, first_seen, last_seen, state, vendor_oui, "
                "vendor_full, ja3_hash, ja3_label, ips, hostnames) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (mac, now, now, "Active", mac[:8], vendor, ja3_hash, ja3_label, ips, hostnames),
            )
            self._log_history(mac, "Active", f"first seen via {event_type}")
            transition = ("New", "Active")
        else:
            prev_state = asset["state"]
            ips = json.loads(asset["ips"] or "[]")
            hostnames = json.loads(asset["hostnames"] or "[]")
            if ip and ip not in ips:
                ips.append(ip)
            if hostname and hostname not in hostnames:
                hostnames.append(hostname)

            # Keep the existing vendor_full/ja3 unless this event supplies
            # a better (non-null) value -- vendor rarely changes, but a
            # JA3 hash is only available on TLS events, so don't overwrite
            # a known fingerprint with null on a later ARP/SYN event.
            new_vendor = vendor or asset["vendor_full"]
            new_ja3_hash = ja3_hash or asset["ja3_hash"]
            new_ja3_label = ja3_label or asset["ja3_label"]

            if prev_state == "Decommissioned":
                new_state = "Reactivated"
            elif prev_state in ("Orphaned", "Idle"):
                new_state = "Active"
            else:
                new_state = prev_state

            self.conn.execute(
                "UPDATE assets SET last_seen = ?, state = ?, ips = ?, hostnames = ?, "
                "vendor_full = ?, ja3_hash = ?, ja3_label = ? WHERE mac = ?",
                (now, new_state, json.dumps(ips), json.dumps(hostnames),
                 new_vendor, new_ja3_hash, new_ja3_label, mac),
            )
            if new_state != prev_state:
                self._log_history(mac, new_state, f"transitioned from {prev_state} via {event_type}")
                transition = (prev_state, new_state)

        self.conn.commit()
        return transition

    def age_assets(self):
        """Sweep all assets, downgrading state based on inactivity.
        Decommissioned is NEVER set automatically -- only via mark_decommissioned,
        simulating a feed from an ITSM/CMDB system.
        """
        now = time.time()
        active_to_idle = self.config["thresholds"]["active_to_idle_seconds"]
        idle_to_orphaned = self.config["thresholds"]["idle_to_orphaned_seconds"]

        rows = self.conn.execute("SELECT * FROM assets").fetchall()
        for row in rows:
            mac, state, last_seen = row["mac"], row["state"], row["last_seen"]
            age = now - last_seen
            new_state = state
            if state == "Active" and age > active_to_idle:
                new_state = "Idle"
            elif state == "Idle" and age > idle_to_orphaned:
                new_state = "Orphaned"
            if new_state != state:
                self.conn.execute("UPDATE assets SET state = ? WHERE mac = ?", (new_state, mac))
                self._log_history(mac, new_state, f"auto-aged from {state} (idle {int(age)}s)")
        self.conn.commit()

    def mark_decommissioned(self, mac):
        """Simulates an ITSM/CMDB feed telling us this asset was retired."""
        asset = self._get_asset(mac)
        if asset is None:
            return False
        self.conn.execute("UPDATE assets SET state = 'Decommissioned' WHERE mac = ?", (mac,))
        self._log_history(mac, "Decommissioned", "manually marked decommissioned via CLI")
        self.conn.commit()
        return True
