# GhostWatch

**A lifecycle-aware, passive asset sentinel.** Instead of asking "what's on
my network right now," GhostWatch asks "what's on my network that
*shouldn't* be" — tracking every device through New → Active → Idle →
Orphaned → Decommissioned, and raising a **CRITICAL** alert the instant a
decommissioned asset reappears.

Built passively: no active scans, no credentials, no agents. It only
listens.

---

## Why this exists

Most inventory/EDR tools assume an asset is online, managed, and known.
That leaves orphaned devices, staged-but-not-yet-deployed hardware, and
"decommissioned" endpoints invisible — which is exactly the blind spot
threat actors (UNC3944, Black Basta, Medusa, among others) have been
documented abusing: reactivating retired endpoints and harvesting
credentials from discarded hardware precisely because nothing is watching
them anymore.

GhostWatch closes that gap for the states everyone else ignores.

---

## What's actually built

**Core lifecycle engine (Phases 1–4)**
- ✅ Passive fingerprint extraction from raw packets (ARP, TCP SYN, DHCP, TLS ClientHello)
- ✅ A real lifecycle state machine (SQLite-backed, append-only history)
- ✅ A rule-based detector with 4 working detections:
  - `DECOMMISSIONED_ASSET_REACTIVATED` (CRITICAL)
  - `SENSITIVE_PORT_ON_STALE_ASSET` (HIGH)
  - `ORPHANED_ASSET_REAPPEARED` (MEDIUM)
  - `UNKNOWN_ASSET_FIRST_SEEN` (LOW — lightweight Shadow-IT flag)
- ✅ Two sensor modes:
  - **Live capture** (`sensor/capture.py`) — real passive sniffing via Scapy, tested against a real Wi-Fi interface
  - **Offline replay** (`sensor/replay.py`) — runs the identical pipeline against a `.pcap` file
- ✅ CLI tools to mark assets decommissioned and check status
- ✅ A Streamlit dashboard with asset table (now including vendor + JA3), alert feed, and per-asset lifecycle timeline
- ✅ Sigma-style rule definitions (`rules/reactivation.yaml`)

**OT/ICS black-box forensic recorder (Phase 5)**
- ✅ A real Modbus TCP slave simulator (`ot/modbus_server.py`, via pymodbus) standing in for a PLC controlling something like a valve or relay
- ✅ Legit vs. attacker traffic generators (`ot/legit_client.py`, `ot/attacker_client.py`) that send genuine Modbus TCP frames over the wire
- ✅ A passive black-box recorder (`ot/black_box.py`) that sniffs traffic and hand-decodes the Modbus MBAP header + PDU directly from packet bytes, logging metadata only in a bounded ring buffer
- ✅ A forensic "rewind" tool (`ot/analyze.py`) that answers exactly the question the WEF flagged OT networks can't answer today

**Real IEEE OUI vendor lookup**
- ✅ `core/oui_lookup.py` — turns raw MACs into real vendor names ("Raspberry Pi Foundation", "Apple, Inc.", etc.) using Scapy's bundled IEEE-derived manufacturer database. Fully offline, no extra dependency, no network calls.
- ✅ Also flags MACs with the locally-administered bit set (typical of MAC randomization on modern phones — itself a useful signal, not a gap).
- ✅ Wired into every fingerprint, stored per-asset, shown in `status` and the dashboard.

**JA3 TLS fingerprinting**
- ✅ `core/ja3.py` — a from-scratch, dependency-free parser of the TLS ClientHello handshake (MBAP-style manual byte parsing, following the [JA3 spec](https://github.com/salesforce/ja3)): TLS version, cipher suites, extensions, elliptic curves, and EC point formats, hashed into the same JA3 fingerprint format used industry-wide.
- ✅ Lets you fingerprint what *software* is talking, not just which port — two different clients (a browser vs. a custom IoT TLS stack) hitting the same port produce different JA3 hashes.
- ✅ Ships with a small illustrative known-hash table; a real deployment would point this at a maintained public JA3 database.

**SIEM export (CEF + JSON)**
- ✅ `core/siem_export.py` — every alert, from every code path (replay, live capture, or the OT demo), is automatically appended to `data/alerts.cef` (ArcSight-style Common Event Format, syslog-forwarder-ready) and `data/alerts.jsonl` (JSON Lines, one valid document per line, ready for Filebeat/Logstash or direct Elasticsearch bulk import).
- ✅ No manual export step — it's wired directly into the detector's alert-raising path.

**Unified single-file entrypoint**
- ✅ `ghostwatch.py` at the project root exposes every capability through one file and one consistent Python interpreter — no more juggling multiple scripts, terminals, or shell environments (this also sidesteps the WSL/PowerShell Python-mismatch issue entirely, since it's always the same interpreter running everything).
- ✅ The OT demo in particular now runs the simulated PLC, the recorder, both traffic generators, and the forensic rewind **all in one process using threads** — no bash orchestration, no subprocess management, no cross-shell state loss.

**Not yet built**: ML-based anomaly scoring, DNP3/S7comm support alongside Modbus, a full public JA3 hash database. The architecture has clean seams for all of these.

---

## File structure

```
ghostwatch/
├── ghostwatch.py                   # UNIFIED ENTRYPOINT -- run everything from here
├── README.md
├── requirements.txt
├── config.yaml                    # thresholds, sensitive ports, approved-asset list
├── core/
│   ├── db.py                      # SQLite schema (assets, state_history, events, alerts)
│   ├── fingerprint.py             # packet -> fingerprint extraction (+ vendor, JA3)
│   ├── state_engine.py            # the lifecycle state machine
│   ├── detector.py                # rule-based risk/alert engine (+ SIEM export hook)
│   ├── oui_lookup.py               # real IEEE MAC vendor lookup
│   ├── ja3.py                      # JA3 TLS ClientHello fingerprinting
│   └── siem_export.py              # CEF + JSON Lines alert export
├── sensor/
│   ├── capture.py                 # LIVE passive sniffing (needs root + real interface)
│   └── replay.py                  # OFFLINE pcap replay (no root needed)
├── cli/
│   ├── decommission.py            # mark an asset Decommissioned (simulates ITSM feed)
│   └── status.py                  # print current assets + alerts to terminal
├── dashboard/
│   └── app.py                     # Streamlit UI
├── rules/
│   └── reactivation.yaml          # Sigma-style detection rule docs
├── scripts/
│   ├── gen_test_traffic.py        # generates real pcaps for testing/demoing
│   ├── gen_ot_incident_pcap.py    # generates a synthetic past-incident pcap
│   └── run_ot_demo.sh             # (legacy) shell-based OT demo runner
├── ot/
│   ├── modbus_server.py           # simulated PLC (real Modbus TCP slave, via pymodbus)
│   ├── legit_client.py            # simulates routine, authorized HMI traffic
│   ├── attacker_client.py         # simulates an unauthorized write-coil command
│   ├── black_box.py               # passive Modbus TCP metadata recorder (ring buffer)
│   ├── replay.py                  # offline: replay a past-incident .pcap into the black box
│   └── analyze.py                 # forensic "rewind" tool
├── data/                          # ghostwatch.db, ot_blackbox.db, alerts.cef/.jsonl, pcaps
└── tests/                         # (reserved for future automated tests)
```

---

## Setup

```bash
cd ghostwatch
pip install -r requirements.txt
# On Linux, live capture may also require: sudo apt install libpcap-dev
```

Requires Python 3.9+.

---

## How to run it (the easy way — one file for everything)

Every capability is reachable through `ghostwatch.py`:

```bash
pip install -r requirements.txt

# Generate synthetic test traffic (real Raspberry Pi vendor OUI + a real TLS ClientHello)
python ghostwatch.py gen-test-traffic

# Replay it through the full detection pipeline
python ghostwatch.py replay data/initial_traffic.pcap

# Check status -- now shows real vendor names and JA3 fingerprints too
python ghostwatch.py status

# Mark the ghost device decommissioned, then replay its "reactivation"
python ghostwatch.py decommission b8:27:eb:00:00:99
python ghostwatch.py replay data/reactivation_traffic.pcap
python ghostwatch.py status

# See the CEF/JSON SIEM export files that were generated automatically
python ghostwatch.py siem-info

# Look up any MAC's real vendor directly
python ghostwatch.py vendor 3c:22:fb:12:34:56

# Launch the dashboard
python ghostwatch.py dashboard

# Live capture (needs root/admin + a real interface)
sudo python ghostwatch.py live eth0

# Run the entire OT/Modbus black-box scenario in ONE process (no shell scripting)
# --iface auto-detects per OS ("lo" on Linux, "Loopback Pseudo-Interface 1" on
# Windows); override with --iface if list-interfaces shows a different name
python ghostwatch.py ot-demo --port 5030 --duration 8

# If interface auto-detection doesn't match your system, find the exact name:
python ghostwatch.py list-interfaces
```

Run `python ghostwatch.py --help` or `python ghostwatch.py <command> --help` for the full list and options.

---

## Running each piece by hand (the old way, still supported)

### Option A — Offline demo (no root, no real network needed)

```bash
# 1. Generate synthetic test traffic (creates two real .pcap files)
python scripts/gen_test_traffic.py

# 2. Replay the initial traffic - discovers 4 devices
python sensor/replay.py data/initial_traffic.pcap

# 3. Check status - all 4 devices should show state=Active
python cli/status.py

# 4. Mark the "ghost" device as decommissioned
#    (MAC printed by step 1: b8:27:eb:00:00:99)
python cli/decommission.py b8:27:eb:00:00:99

# 5. Replay the reactivation traffic - the "decommissioned" device
#    comes back online and hits RDP (port 3389)
python sensor/replay.py data/reactivation_traffic.pcap

# 6. Check status again
python cli/status.py
```

### Option B — Live passive capture (real deployment)

```bash
# Find your interface name first: ip link  (Linux) or ifconfig (macOS)
sudo python sensor/capture.py eth0
```

Run this on a box connected to a switch SPAN/mirror port for real passive
monitoring. On a flat home/test network you can point it at your own
interface, but you'll only see broadcast/multicast and your own host's
traffic — a mirror port is what makes this genuinely useful.

### Option C — Dashboard

```bash
streamlit run dashboard/app.py
```
Then open the printed `localhost` URL. Run this *after* you've generated
some data via Option A or B, or the tables will be empty.

---

## How to verify it's actually working (expected output)

After running **Option A** steps 1–6 above (or the equivalent `ghostwatch.py`
commands), `python ghostwatch.py status` should end with output containing
these lines (device state, real vendor, and alert list):

```
b8:27:eb:00:00:99    state=Reactivated   vendor=Raspberry Pi Foundation    ...

=== ALERTS ===
[HIGH    ] SENSITIVE_PORT_ON_STALE_ASSET    mac=b8:27:eb:00:00:99 ... contacting sensitive port 3389.
[CRITICAL] DECOMMISSIONED_ASSET_REACTIVATED mac=b8:27:eb:00:00:99 ... reappeared on the network (exact MAC match -> high-confidence reactivation).
[LOW     ] UNKNOWN_ASSET_FIRST_SEEN         mac=b8:27:eb:00:00:99 ...
[LOW     ] UNKNOWN_ASSET_FIRST_SEEN         mac=aa:bb:cc:00:00:03 ...
[LOW     ] UNKNOWN_ASSET_FIRST_SEEN         mac=aa:bb:cc:00:00:02 ...
[LOW     ] UNKNOWN_ASSET_FIRST_SEEN         mac=aa:bb:cc:00:00:01 ...
```

**If you see the `CRITICAL DECOMMISSIONED_ASSET_REACTIVATED` line and a
real vendor name (not "Unknown") for that device, the core detection
engine — including the new OUI vendor lookup — is working correctly.**

To also confirm SIEM export and JA3 are working:
```bash
python ghostwatch.py siem-info   # should show non-empty CEF and JSON files
python -c "
import sqlite3
c = sqlite3.connect('data/ghostwatch.db')
print(c.execute('SELECT mac, ja3_hash FROM assets WHERE ja3_hash IS NOT NULL').fetchall())
"
# should print one row -- the device that sent the synthetic TLS ClientHello
```

To reset and re-run from scratch at any point:
```bash
rm -f data/ghostwatch.db data/alerts.cef data/alerts.jsonl data/ot_blackbox.db
```

### Sanity checks if something looks wrong

| Symptom | Likely cause |
|---|---|
| `ModuleNotFoundError: No module named 'scapy'` | Run `pip install -r requirements.txt` again -- and make sure `pip` and `python`/`python3` resolve to the *same* environment (a common trap when mixing WSL and PowerShell, or system Python and a venv) |
| `decommission` says "not found in database" | Run the replay of `initial_traffic.pcap` first — the asset has to be seen once before it can be decommissioned |
| No `Reactivated` state after step 5 | Confirm you used the exact MAC printed in step 1 for the decommission command |
| Dashboard shows empty tables | Run Option A first — the dashboard only reads `data/ghostwatch.db`, it doesn't generate data |
| Permission denied on live capture | Live capture needs root/sudo — this is a raw-socket requirement, not a bug |
| `ot-demo` says "Address already in use" | A previous run's PLC server on the same port may still be releasing; wait a few seconds or pass a different `--port` |
| `ot-demo` says "Interface 'lo' not found" (Windows) | Windows has no interface literally named `lo`. `ghostwatch.py` auto-detects `"Loopback Pseudo-Interface 1"` as the Windows default, but if your Npcap install names it differently, run `python ghostwatch.py list-interfaces` to see the exact name and pass it via `--iface "..."` |
| Vendor shows "Unknown" for a MAC you expect to resolve | Either it's a randomized/locally-administered MAC (`python ghostwatch.py vendor <mac>` will say so explicitly) or a genuinely unregistered/newer OUI not yet in Scapy's bundled database |

---

## Running the OT black-box demo (Phase 5)

The fastest way, in a single process, no shell scripting needed:

```bash
python ghostwatch.py ot-demo --port 5030 --duration 8
```

This starts the simulated PLC, the passive recorder, sends legitimate
HMI traffic, sends the unauthorized attacker command, then runs the
forensic rewind — all inside one Python process using threads, which
sidesteps any shell/venv/interpreter mismatch entirely.

### Real deployment: continuous recording + investigating later

`ot-demo` is a self-contained *demo* (simulated PLC, simulated traffic).
For an actual OT network, the workflow splits into two independent
pieces:

**1. Record continuously**, on a box connected to the OT network (needs
root/admin for raw sniffing):
```bash
sudo python ghostwatch.py ot-live eth0 --port 502
```
This runs indefinitely (Ctrl+C to stop), passively logging every Modbus
write command's metadata to `data/ot_blackbox.db` — a rolling ring
buffer of the last 5,000 events. No simulated traffic, no demo clients,
just real passive recording.

**2. Investigate at any later point** — days later, after an incident is
reported — by querying that same database directly, without starting a
new capture:
```bash
python ghostwatch.py ot-rewind                # everything on file
python ghostwatch.py ot-rewind --coil 7        # narrow to one coil
python ghostwatch.py ot-rewind --since 3600    # narrow to the last hour
```

### Investigating an incident GhostWatch DIDN'T record live

If something happened *before* GhostWatch was deployed, but someone
else already captured the traffic (a switch mirror, a tap, a
colleague's Wireshark session, a vendor's incident report), hand that
`.pcap` to the offline OT replay mode instead — no live recording
required:
```bash
python ghostwatch.py ot-replay path/to/incident.pcap --port 502
python ghostwatch.py ot-rewind
```
This parses the same Modbus frames from the file that the live recorder
would have parsed off the wire, and — importantly — uses the **capture's
own embedded timestamps**, not "now", so the forensic timeline reflects
when the incident actually happened.

A synthetic example of exactly this scenario is included:
```bash
python ghostwatch.py gen-ot-incident   # or: python scripts/gen_ot_incident_pcap.py
python ghostwatch.py ot-replay data/ot_incident.pcap --port 502
python ghostwatch.py ot-rewind
```
This generates a 3-days-in-the-past capture with routine engineer
maintenance (internal IP, expected hours) followed by an unauthorized
write from an external IP at 2:14 AM — then reconstructs that entire
timeline as if you'd just received the file from an incident responder.

Or run each piece by hand to understand what's happening:

```bash
# Terminal 1: the simulated PLC
python3 ot/modbus_server.py 5030

# Terminal 2: the black-box recorder (needs root/admin for raw sniffing)
sudo python3 ot/black_box.py lo 5030      # Linux, loopback
# sudo python3 ot/black_box.py "Ethernet" 502   # Windows/real network, real Modbus port

# Terminal 3: generate traffic
python3 ot/legit_client.py 5030            # normal operator activity
python3 ot/attacker_client.py 5030         # the "Norwegian dam" scenario

# Then, any time after, the forensic rewind:
python3 ot/analyze.py
python3 ot/analyze.py --coil 7             # narrow to a specific coil
python3 ot/analyze.py --since 60           # narrow to the last 60 seconds
```

**Expected output** — the attacker's write-coil command clearly separated
from the legit HMI's routine activity, on a different coil:

```
[2026-XX-XX HH:MM:SS] Write Single Coil      source=127.0.0.1:xxxxx  -> plc=127.0.0.1:5030  address=2  value=1
[2026-XX-XX HH:MM:SS] Write Single Coil      source=127.0.0.1:xxxxx  -> plc=127.0.0.1:5030  address=2  value=0
[2026-XX-XX HH:MM:SS] Write Single Coil      source=127.0.0.1:yyyyy  -> plc=127.0.0.1:5030  address=7  value=1
```

The last line — a write to a *different* coil, arriving after the
legitimate session ended — is the injected "attack." In a real
deployment, source_ip would be a genuinely different, unauthorized host
on the OT network, which is an even stronger signal than what this
single-host demo can show.

**Note on loopback captures**: sniffing the `lo` interface on Linux
causes the kernel to hand back each packet twice (once per direction of
the loopback path). `ot/analyze.py`'s `rewind()` de-duplicates by
transaction ID so this doesn't appear as double-counted events — this is
purely a loopback testing artifact and won't occur capturing a real
physical link.

---

## Design notes worth knowing (for interviews / code review)

- **Decommissioned is never auto-set.** Only a manual call (or, in
  production, an ITSM webhook) can decommission an asset. Time-based aging
  only ever moves an asset to `Idle` or `Orphaned` — this avoids a
  dangerous false negative where a temporarily-quiet device gets silently
  marked as retired.
- **Reactivation is a distinct state, not a silent merge back into
  `Active`.** This is deliberate: folding it back into `Active` would
  destroy the forensic signal. `state_history` preserves the full "asset
  story" for every device, which is what elevates this from a monitor to
  a forensic tool.
- **Confidence vs. severity are tracked separately** in the `alerts`
  table. A MAC-exact match on reactivation is high-confidence; future
  detections based on fuzzier signals (IP reuse, hostname similarity)
  should be scored lower even at the same severity, to keep the alert
  feed trustworthy.
- **Rules are explainable, not ML**, on purpose for v1 — every alert in
  this system can be traced to a one-line condition in `detector.py` and
  documented in Sigma format in `rules/`. That's a stronger story in a
  SOC context than an opaque model with unclear false-positive behavior.
