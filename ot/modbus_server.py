"""
Simulated PLC -- a real Modbus TCP slave, not a mock.

This stands in for a physical PLC controlling something like a valve or
relay via its coils. GhostWatch's OT black-box recorder (black_box.py)
listens to the real Modbus TCP traffic exchanged with this server and
logs it, exactly as it would against a real PLC on a real OT network.

Usage:
    python ot/modbus_server.py [port]

Default port is 5020 (works without root). Real Modbus TCP is port 502,
which requires root/admin to bind -- pass 502 explicitly if running with
elevated privileges and you want to be fully realistic.
"""
import sys
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)
from pymodbus.server import StartTcpServer


def main(port=5020):
    # 100 coils, all initialized to 0 (OFF). In a real dam/valve controller,
    # coil 0 might be "intake valve open/closed", etc.
    device = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(1, [0] * 100),
        co=ModbusSequentialDataBlock(1, [0] * 100),
        hr=ModbusSequentialDataBlock(1, [0] * 100),
        ir=ModbusSequentialDataBlock(1, [0] * 100),
    )
    context = ModbusServerContext(devices=device, single=True)

    print(f"[+] Simulated PLC (Modbus TCP) listening on 127.0.0.1:{port}")
    print("[+] Coils 0-99 all initialized to OFF. Ctrl+C to stop.")
    StartTcpServer(context=context, address=("127.0.0.1", port))


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 5020
    main(p)
