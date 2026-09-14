#!/bin/bash
set -e
# Resolve to the project root based on this script's own location,
# instead of a hardcoded path -- works no matter where the project
# folder actually lives on your machine.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
rm -f data/ot_blackbox.db

PORT=${1:-5030}
echo "=== 1. Starting simulated PLC on port $PORT ==="
python3 ot/modbus_server.py $PORT > /tmp/plc_server.log 2>&1 &
PLC_PID=$!
sleep 1.5
tail -2 /tmp/plc_server.log

echo ""
echo "=== 2. Starting OT black-box recorder (sniffing loopback) ==="
python3 ot/black_box.py lo $PORT > /tmp/blackbox.log 2>&1 &
BB_PID=$!
sleep 1.5
cat /tmp/blackbox.log

echo ""
echo "=== 3. LEGITIMATE HMI traffic (routine polling + authorized valve close on coil 2) ==="
python3 ot/legit_client.py $PORT
sleep 1

echo ""
echo "=== 4. ATTACKER traffic (unauthorized write to coil 7 - Norwegian dam scenario) ==="
python3 ot/attacker_client.py $PORT
sleep 1.5

echo ""
echo "=== 5. Stopping capture ==="
kill -9 $PLC_PID $BB_PID 2>/dev/null || true
sleep 0.5

echo ""
echo "=== 6. FORENSIC REWIND ==="
python3 ot/analyze.py

echo ""
echo "=== DONE ==="
