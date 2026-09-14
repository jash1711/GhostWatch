"""
GhostWatch dashboard.

Run with:
    streamlit run dashboard/app.py

(run from the project root so config.yaml and core/ resolve correctly)
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import yaml
import pandas as pd
from core.db import get_conn

st.set_page_config(page_title="GhostWatch", layout="wide", page_icon="dashboard/assets/logo.png")

with open("config.yaml") as f:
    config = yaml.safe_load(f)

conn = get_conn(config["db_path"])

col_logo, col_title = st.columns([1, 7])
with col_logo:
    st.image("dashboard/assets/logo.png", width=110)
with col_title:
    st.title("GhostWatch — Lifecycle-Aware Asset Sentinel")
    st.caption("Discovers assets passively and tracks them across their full lifecycle, "
               "including the states everyone else's tooling ignores.")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Assets")
    assets = pd.read_sql_query(
        "SELECT mac, state, vendor_full, ja3_hash, ja3_label, ips, hostnames, first_seen, last_seen "
        "FROM assets ORDER BY last_seen DESC",
        conn,
    )
    st.dataframe(assets, width='stretch')

with col2:
    st.subheader("Alerts")
    alerts = pd.read_sql_query(
        "SELECT severity, alert_type, mac, ip, detail, timestamp FROM alerts ORDER BY timestamp DESC",
        conn,
    )
    st.dataframe(alerts, width='stretch')

st.subheader("Asset Timeline")
macs = [row["mac"] for row in conn.execute("SELECT DISTINCT mac FROM state_history").fetchall()]
if macs:
    selected = st.selectbox("Select an asset MAC to view its lifecycle history", macs)
    if selected:
        hist = pd.read_sql_query(
            "SELECT state, timestamp, evidence FROM state_history WHERE mac=? ORDER BY timestamp ASC",
            conn,
            params=(selected,),
        )
        st.table(hist)
else:
    st.info("No asset history yet -- run the sensor or replay mode first.")
