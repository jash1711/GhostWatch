"""
Simulates the attack scenario from the source brief: an unauthorized
client issuing a "write coil" command it has no business sending --
mirroring the April 2025 Norwegian dam incident, where a weak password
let an attacker manipulate a valve and go undetected for four hours.

This is a REAL Modbus TCP "write single coil" command sent over the
network to the simulated PLC -- not a log entry faked after the fact.
The black-box recorder has to actually observe it on the wire.

Usage:
    python ot/attacker_client.py [port]
"""
import sys
from pymodbus.client import ModbusTcpClient


def main(port=5020):
    # Ephemeral source port (see legit_client.py for why we don't pin one).
    # In this demo, the write goes to a DIFFERENT coil (7, vs. the legit
    # client's coil 2) -- on a real network the giveaway would be the
    # source IP; here it's the coil address plus arriving out of the
    # normal operator's sequence.
    client = ModbusTcpClient("127.0.0.1", port=port)
    if not client.connect():
        print("[!] Could not connect to PLC -- is modbus_server.py running?")
        return

    print("[!] Sending UNAUTHORIZED write-coil command (simulating attacker)...")
    # Coil 7 = "intake valve" in this scenario. Attacker forces it OPEN.
    client.write_coil(address=7, value=True)

    client.close()
    print("[!] Attacker command sent and connection closed.")


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 5020
    main(p)
