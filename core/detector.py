"""
Rule-based detection engine. Deliberately NOT machine learning for v1 --
transparent, explainable rules are more trustworthy and more defensible
in an interview or a SOC than a black-box model, and they map directly
to the Sigma-style rules in rules/reactivation.yaml.

Every alert raised here is also immediately exported to CEF and JSON
Lines via core.siem_export, so the alert feed is SIEM-ready in real time,
not just queryable from GhostWatch's own SQLite database.
"""
import time
from core.siem_export import export_alert

SENSITIVE_PORTS_DEFAULT = {22, 23, 3389, 445, 21, 5900}


class Detector:
    def __init__(self, conn, config):
        self.conn = conn
        self.sensitive_ports = set(config.get("sensitive_ports", SENSITIVE_PORTS_DEFAULT))
        self.approved = set(config.get("approved_assets", []))

    def _raise_alert(self, mac, ip, alert_type, severity, confidence, detail):
        ts = time.time()
        self.conn.execute(
            "INSERT INTO alerts (mac, ip, alert_type, severity, confidence, timestamp, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (mac, ip, alert_type, severity, confidence, ts, detail),
        )
        self.conn.commit()
        export_alert(alert_type, severity, mac, ip, detail, confidence, ts)

    def evaluate_transition(self, mac, ip, transition):
        if transition is None:
            return
        from_state, to_state = transition

        if to_state == "Reactivated":
            self._raise_alert(
                mac, ip, "DECOMMISSIONED_ASSET_REACTIVATED", "CRITICAL", "HIGH",
                f"Asset {mac} was marked Decommissioned and reappeared on the network "
                f"(exact MAC match -> high-confidence reactivation).",
            )
        elif from_state == "Orphaned" and to_state == "Active":
            self._raise_alert(
                mac, ip, "ORPHANED_ASSET_REAPPEARED", "MEDIUM", "MEDIUM",
                f"Asset {mac} was Orphaned and became Active again.",
            )
        elif from_state == "New" and to_state == "Active" and mac not in self.approved:
            self._raise_alert(
                mac, ip, "UNKNOWN_ASSET_FIRST_SEEN", "LOW", "MEDIUM",
                f"New unrecognized asset {mac} seen for the first time (not in approved list).",
            )

    def evaluate_port_event(self, mac, ip, state, port):
        if port in self.sensitive_ports and state in ("Orphaned", "Decommissioned", "Reactivated"):
            self._raise_alert(
                mac, ip, "SENSITIVE_PORT_ON_STALE_ASSET", "HIGH", "HIGH",
                f"Asset {mac} in state {state} was observed contacting sensitive port {port}.",
            )
