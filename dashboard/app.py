from streamlit_autorefresh import st_autorefresh
import streamlit as st
import sqlite3
import pandas as pd
import os
import plotly.express as px

# ------------------ PAGE CONFIG ------------------
st.set_page_config(
    page_title="Healthcare IoT Honeypot",
    page_icon="🏥",
    layout="wide"
)

# Auto Refresh every 5 seconds
st_autorefresh(interval=5000, key="refresh")

# ------------------ DATABASE ------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "database", "attacks.db")

conn = sqlite3.connect(DB_PATH)
df = pd.read_sql_query("SELECT * FROM attacks", conn)
conn.close()

# ------------------ HEADER ------------------
st.title("🏥 Healthcare IoT Honeypot Dashboard")
st.caption("Real-Time Healthcare IoT Intrusion Detection Dashboard")

st.success("🟢 Honeypot Status : ONLINE")

st.markdown("---")

# ------------------ METRICS ------------------
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🚨 Total Events", len(df))

with col2:
    st.metric("🌍 Unique Attackers", df["attacker_ip"].nunique())

with col3:
    st.metric(
        "👤 Usernames Tried",
        df["username"].replace("", pd.NA).dropna().nunique()
    )

with col4:
    st.metric(
        "🔑 Password Attempts",
        df["password"].replace("", pd.NA).dropna().count()
    )

st.markdown("---")

# ------------------ TWO COLUMN LAYOUT ------------------
left, right = st.columns([2, 1])

# ================= LEFT =================
with left:

    st.subheader("📋 Captured Attack Logs")

    search = st.text_input("🔍 Search by IP Address or Username")

    if search:
        filtered = df[
            df["attacker_ip"].astype(str).str.contains(search, case=False, na=False)
            |
            df["username"].astype(str).str.contains(search, case=False, na=False)
        ]
    else:
        filtered = df

    st.dataframe(filtered, use_container_width=True)

    csv = filtered.to_csv(index=False).encode("utf-8")

    st.download_button(
        "📥 Download Attack Logs",
        csv,
        "attack_logs.csv",
        "text/csv"
    )

# ================= RIGHT =================
with right:

    st.subheader("📊 Event Distribution")

    event_counts = (
        df["event"]
        .fillna("Unknown")
        .value_counts()
        .reset_index()
    )

    event_counts.columns = ["Event", "Count"]

    fig = px.pie(
        event_counts,
        names="Event",
        values="Count",
        hole=0.45,
        title="Attack Events"
    )

    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ------------------ TIMELINE ------------------
st.subheader("📈 Attack Timeline")

timeline = (
    df.groupby("timestamp")
      .size()
      .reset_index(name="Attacks")
)

fig2 = px.line(
    timeline,
    x="timestamp",
    y="Attacks",
    markers=True,
    title="Attack Timeline"
)

st.plotly_chart(fig2, use_container_width=True)

# ------------------ TOP ATTACKERS ------------------
st.markdown("---")

st.subheader("📌 Top Attacker IPs")

ip_counts = (
    df["attacker_ip"]
    .value_counts()
    .reset_index()
)

ip_counts.columns = ["IP Address", "Attempts"]

st.dataframe(ip_counts, use_container_width=True)

# ------------------ RAW DATABASE ------------------
with st.expander("🗄 View Complete Database"):

    st.dataframe(df, use_container_width=True)

# ------------------ FOOTER ------------------
st.markdown("---")

st.caption(
    "Healthcare IoT Honeypot | Cowrie + SQLite + Streamlit | Developed by Deepak Kumar"
)