"""
Simulates a legitimate SCADA/HMI client: periodically reads coil status
(normal polling) and occasionally issues an authorized "write coil"
command -- e.g. an operator closing a valve on schedule.

This traffic should look unremarkable to the black-box recorder. It's
here to give the forensic timeline realistic "noise" so the malicious
command in attacker_client.py has to be found among legitimate activity,
not just be the only entry in an empty log.

Usage:
    python ot/legit_client.py [port]
"""
import sys
import time
from pymodbus.client import ModbusTcpClient


def main(port=5020):
    # Let the OS assign an ephemeral source port rather than binding a fixed
    # one -- a fixed port causes TCP TIME_WAIT collisions on repeated demo
    # runs. On a real network, source IP is what naturally distinguishes
    # sessions; here, the coil address + timing does that job instead.
    client = ModbusTcpClient("127.0.0.1", port=port)
    if not client.connect():
        print("[!] Could not connect to PLC -- is modbus_server.py running?")
        return

    print("[+] Legit HMI client connected. Polling coils and issuing routine commands...")

    # Normal polling: read coil status (function code 0x01)
    for _ in range(3):
        client.read_coils(address=0, count=10)
        time.sleep(0.3)

    # One authorized, routine action: operator closes coil 2 (e.g. a valve)
    client.write_coil(address=2, value=True)
    time.sleep(0.3)
    client.write_coil(address=2, value=False)
    time.sleep(0.3)

    client.close()
    print("[+] Legit client finished its session.")


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 5020
    main(p)
