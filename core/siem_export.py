"""
SIEM export: turns every GhostWatch alert into two industry-standard,
ingestible formats as it's raised, in real time:

  - CEF (Common Event Format) -- the format ArcSight/many SIEMs and
    syslog-based pipelines expect. One line per alert, appended to
    data/alerts.cef, ready to point a syslog forwarder or file input at.
  - JSON Lines -- one JSON object per line, appended to
    data/alerts.jsonl, ready for Filebeat/Logstash or a direct Elasticsearch
    bulk import (each line is already a valid single document).

CEF spec: CEF:Version|Device Vendor|Device Product|Device Version|
          Signature ID|Name|Severity|Extension
"""
import json
import os
import time

CEF_PATH = "data/alerts.cef"
JSON_PATH = "data/alerts.jsonl"

# CEF severity is an integer 0-10. Map our text severities onto that scale.
SEVERITY_TO_CEF = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
}


def _cef_escape(value):
    """CEF requires escaping backslash, pipe, and equals in extension values."""
    if value is None:
        return ""
    value = str(value)
    return value.replace("\\", "\\\\").replace("=", "\\=")


def to_cef(alert_type, severity, mac, ip, detail, confidence=None):
    cef_severity = SEVERITY_TO_CEF.get(severity, 5)
    ext_parts = [
        f"src={_cef_escape(ip)}",
        f"smac={_cef_escape(mac)}",
        f"cat={_cef_escape(alert_type)}",
        f"msg={_cef_escape(detail)}",
    ]
    if confidence:
        ext_parts.append(f"cs1={_cef_escape(confidence)}")
        ext_parts.append("cs1Label=Confidence")

    extension = " ".join(ext_parts)
    return (
        f"CEF:0|GhostWatch|AssetSentinel|1.0|{alert_type}|"
        f"{alert_type.replace('_', ' ').title()}|{cef_severity}|{extension}"
    )


def to_json_line(alert_type, severity, mac, ip, detail, confidence=None, timestamp=None):
    record = {
        "timestamp": timestamp or time.time(),
        "product": "GhostWatch",
        "alert_type": alert_type,
        "severity": severity,
        "confidence": confidence,
        "src_mac": mac,
        "src_ip": ip,
        "message": detail,
    }
    return json.dumps(record)


def export_alert(alert_type, severity, mac, ip, detail, confidence=None, timestamp=None):
    """Append this alert to both the CEF and JSON Lines files.
    Safe to call on every alert -- both are simple append-only writes.
    """
    for path in (CEF_PATH, JSON_PATH):
        dirpath = os.path.dirname(path)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

    with open(CEF_PATH, "a") as f:
        f.write(to_cef(alert_type, severity, mac, ip, detail, confidence) + "\n")

    with open(JSON_PATH, "a") as f:
        f.write(to_json_line(alert_type, severity, mac, ip, detail, confidence, timestamp) + "\n")
