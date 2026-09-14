"""
Generates a synthetic "past incident" pcap: real Modbus TCP write-coil
frames from a legitimate engineering workstation and an unauthorized
external host, timestamped several days in the past -- simulating a
capture an incident responder hands you AFTER something already
happened, rather than traffic GhostWatch watched live.

This proves ot/replay.py's forensic-timeline reconstruction: the
capture's own embedded timestamps are what analyze.py/ot-rewind reports,
not "now".

Usage:
    python scripts/gen_ot_incident_pcap.py
"""
import struct
import time
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PLC_IP = "10.20.30.5"
ENGINEER_IP = "10.20.30.40"     # the legitimate workstation
ATTACKER_IP = "203.0.113.77"    # an unauthorized external host

# Set the "incident" 3 days in the past, at 02:14 local time -- an
# unusual hour for legitimate maintenance, which is itself a signal.
_three_days_ago = time.localtime(time.time() - 3 * 86400)
INCIDENT_TIME = time.mktime((
    _three_days_ago.tm_year, _three_days_ago.tm_mon, _three_days_ago.tm_mday,
    2, 14, 0, 0, 0, -1
))


def modbus_write_coil_frame(transaction_id, unit_id, address, turn_on):
    mbap = struct.pack("!HHHB", transaction_id, 0, 6, unit_id)
    value = 0xFF00 if turn_on else 0x0000
    pdu = struct.pack("!BHH", 0x05, address, value)
    return mbap + pdu


def make_pkt(src_ip, dst_ip, sport, dport, payload, ts):
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=payload)
    pkt.time = ts
    return pkt


def build():
    packets = []

    # Routine maintenance earlier that same night -- normal engineer activity
    packets.append(make_pkt(
        ENGINEER_IP, PLC_IP, 52110, 502,
        modbus_write_coil_frame(1, 1, address=3, turn_on=True),
        INCIDENT_TIME - 900,
    ))
    packets.append(make_pkt(
        ENGINEER_IP, PLC_IP, 52110, 502,
        modbus_write_coil_frame(2, 1, address=3, turn_on=False),
        INCIDENT_TIME - 870,
    ))

    # The incident: an unauthorized write from an external IP, opening
    # coil 7 (standing in for an intake valve) at an unusual hour.
    packets.append(make_pkt(
        ATTACKER_IP, PLC_IP, 44980, 502,
        modbus_write_coil_frame(1, 1, address=7, turn_on=True),
        INCIDENT_TIME,
    ))

    wrpcap("data/ot_incident.pcap", packets)
    incident_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(INCIDENT_TIME))
    print("[+] Wrote data/ot_incident.pcap")
    print(f"[+] Simulated incident timestamp: {incident_str} (3 days ago)")
    print(f"[+] Attacker source IP to look for: {ATTACKER_IP}")


if __name__ == "__main__":
    build()
