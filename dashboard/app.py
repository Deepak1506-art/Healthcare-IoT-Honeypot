import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import os
from datetime import datetime

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Healthcare IoT Honeypot",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# DATABASE
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(
    os.path.join(BASE_DIR, "..", "database", "attacks.db")
)


@st.cache_data(ttl=10)
def load_data():
    try:
        conn = sqlite3.connect(DB_PATH)

        df = pd.read_sql_query(
            """
            SELECT
                id,
                timestamp,
                attacker_ip,
                username,
                password,
                event
            FROM attacks
            ORDER BY id DESC
            """,
            conn
        )

        conn.close()

        return df

    except Exception as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame(
            columns=[
                "id",
                "timestamp",
                "attacker_ip",
                "username",
                "password",
                "event"
            ]
        )


df = load_data()

# ============================================================
# GLOBAL CSS
# ============================================================

st.markdown(
    """
<style>

.stApp {
    background: #07111f;
    color: #e8eef7;
}

section[data-testid="stSidebar"] {
    background: #091827;
    border-right: 1px solid #1d344a;
}

section[data-testid="stSidebar"] * {
    color: #e8eef7;
}

.block-container {
    max-width: 1500px;
    padding-top: 2rem;
}

.hero {
    background: linear-gradient(135deg, #102d46, #0b1727);
    border: 1px solid #244766;
    border-radius: 18px;
    padding: 28px;
    margin-bottom: 22px;
}

.hero-title {
    font-size: 32px;
    font-weight: 800;
}

.hero-subtitle {
    color: #91a9bd;
    margin-top: 7px;
    font-size: 15px;
}

.status-online {
    display: inline-block;
    margin-top: 18px;
    padding: 7px 13px;
    border-radius: 20px;
    background: #103b2d;
    color: #5ff0b1;
    border: 1px solid #246d54;
    font-size: 13px;
    font-weight: 700;
}

.card {
    background: #0c1b2b;
    border: 1px solid #1c344a;
    border-radius: 15px;
    padding: 20px;
    min-height: 120px;
}

.card-title {
    color: #8298ad;
    font-size: 13px;
}

.card-value {
    font-size: 29px;
    font-weight: 800;
    margin-top: 8px;
}

.section-title {
    font-size: 23px;
    font-weight: 800;
    margin: 10px 0 18px;
}

.search-box {
    background: #0b1d2f;
    border: 1px solid #285071;
    border-radius: 15px;
    padding: 20px;
    margin-bottom: 22px;
}

.result-card {
    background: #0b1c2c;
    border: 1px solid #24506e;
    border-radius: 15px;
    padding: 20px;
    margin: 10px 0;
}

.good {
    color: #5ff0b1;
}

.warning {
    color: #ffc857;
}

.danger {
    color: #ff6874;
}

</style>
""",
    unsafe_allow_html=True
)

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.markdown("## 🏥 IoT Security")

st.sidebar.caption("Healthcare IoT Honeypot")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Home",
        "🔎 Investigation",
        "🔴 Live Attacks",
        "🚨 Alerts",
        "🛡️ Threats",
        "📡 Devices",
        "📊 Analytics",
        "🗄️ Data Sources",
        "📋 Attack Logs",
        "📑 Reports",
        "⚙️ System Status"
    ]
)

st.sidebar.markdown("---")

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("Healthcare IoT Honeypot")
st.sidebar.caption("Cowrie + SQLite + Streamlit")

# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
<div class="hero">
    <div class="hero-title">🏥 Healthcare IoT Security Center</div>
    <div class="hero-subtitle">
        Honeypot-based intrusion monitoring and attack intelligence platform
    </div>
    <div class="status-online">🟢 HONEYPOT ONLINE</div>
</div>
""",
    unsafe_allow_html=True
)

# ============================================================
# GLOBAL SEARCH
# ============================================================

st.markdown(
    """
<div class="search-box">
    <h3>🔎 Global Security Search</h3>
    <p>
        Search attacker IP, username, event, password attempt or attack ID.
    </p>
</div>
""",
    unsafe_allow_html=True
)

search = st.text_input(
    "Search security activity",
    placeholder="Example: 192.168.1.25, root, login, failed...",
    label_visibility="collapsed"
)

# ============================================================
# SEARCH RESULTS
# ============================================================

if search.strip():

    query = search.strip().lower()

    searchable = df.fillna("").astype(str)

    mask = (
        searchable["attacker_ip"].str.lower().str.contains(query, regex=False)
        |
        searchable["username"].str.lower().str.contains(query, regex=False)
        |
        searchable["password"].str.lower().str.contains(query, regex=False)
        |
        searchable["event"].str.lower().str.contains(query, regex=False)
        |
        searchable["id"].str.lower().str.contains(query, regex=False)
    )

    results = df[mask]

    st.markdown("## 🔍 Investigation Results")

    if results.empty:

        st.warning(
            f"No recorded honeypot activity was found for: `{search}`"
        )

        if "." in search:
            st.info(
                "This IP is not present in the current honeypot database. "
                "The system will not invent attack information."
            )

    else:

        # If search looks like an IP, show dedicated IP investigation
        ip_matches = results[
            results["attacker_ip"].astype(str).str.lower() == query
        ]

        if not ip_matches.empty:

            ip = ip_matches["attacker_ip"].iloc[0]

            st.markdown(f"### 🌐 IP Investigation: `{ip}`")

            total = len(ip_matches)

            usernames = (
                ip_matches["username"]
                .replace("", pd.NA)
                .dropna()
                .unique()
                .tolist()
            )

            events = (
                ip_matches["event"]
                .replace("", pd.NA)
                .dropna()
                .value_counts()
            )

            passwords = (
                ip_matches["password"]
                .replace("", pd.NA)
                .dropna()
                .nunique()
            )

            first_seen = ip_matches["timestamp"].min()
            last_seen = ip_matches["timestamp"].max()

            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.metric("🚨 Total Events", total)

            with c2:
                st.metric("👤 Usernames", len(usernames))

            with c3:
                st.metric("🔑 Passwords", passwords)

            with c4:
                st.metric("⚡ Event Types", len(events))

            st.markdown("### 🧠 Threat Intelligence")

            a, b = st.columns(2)

            with a:

                st.markdown(
                    f"""
                    <div class="result-card">
                    <b>Attacker IP</b><br>
                    {ip}<br><br>

                    <b>First Seen</b><br>
                    {first_seen}<br><br>

                    <b>Last Seen</b><br>
                    {last_seen}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with b:

                username_text = (
                    ", ".join(map(str, usernames))
                    if usernames
                    else "No usernames captured"
                )

                st.markdown(
                    f"""
                    <div class="result-card">
                    <b>Usernames Attempted</b><br>
                    {username_text}<br><br>

                    <b>Most Common Events</b><br>
                    {events.head(5).to_string()}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            # Timeline
            st.markdown("### 📈 Attacker Activity Timeline")

            ip_timeline = (
                ip_matches
                .groupby("timestamp")
                .size()
                .reset_index(name="Events")
            )

            if not ip_timeline.empty:

                fig = px.line(
                    ip_timeline,
                    x="timestamp",
                    y="Events",
                    markers=True,
                    title=f"Activity from {ip}"
                )

                fig.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="#0b1c2c",
                    plot_bgcolor="#0b1c2c"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

            st.markdown("### 📋 Complete Activity From This IP")

            st.dataframe(
                ip_matches,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.markdown(
                f"### 🔎 Records matching `{search}`"
            )

            st.dataframe(
                results,
                use_container_width=True,
                hide_index=True
            )

    st.markdown("---")

# ============================================================
# HOME
# ============================================================

if page == "🏠 Home":

    st.markdown(
        '<div class="section-title">Security Overview</div>',
        unsafe_allow_html=True
    )

    total_events = len(df)

    unique_ips = (
        df["attacker_ip"].nunique()
        if not df.empty else 0
    )

    usernames = (
        df["username"]
        .replace("", pd.NA)
        .dropna()
        .nunique()
        if not df.empty else 0
    )

    passwords = (
        df["password"]
        .replace("", pd.NA)
        .dropna()
        .count()
        if not df.empty else 0
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("🚨 Total Events", total_events)

    with c2:
        st.metric("🌐 Unique Attackers", unique_ips)

    with c3:
        st.metric("👤 Usernames Tried", usernames)

    with c4:
        st.metric("🔑 Password Attempts", passwords)

    st.markdown("---")

    if not df.empty:

        left, right = st.columns(2)

        with left:

            st.markdown("### 📊 Event Distribution")

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
                hole=0.45
            )

            fig.update_layout(
                template="plotly_dark"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        with right:

            st.markdown("### 🌐 Top Attacker IPs")

            ip_counts = (
                df["attacker_ip"]
                .value_counts()
                .head(10)
                .reset_index()
            )

            ip_counts.columns = [
                "IP Address",
                "Attempts"
            ]

            fig = px.bar(
                ip_counts,
                x="Attempts",
                y="IP Address",
                orientation="h"
            )

            fig.update_layout(
                template="plotly_dark"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

# ============================================================
# INVESTIGATION
# ============================================================

elif page == "🔎 Investigation":

    st.markdown(
        '<div class="section-title">🔎 Attacker Investigation Center</div>',
        unsafe_allow_html=True
    )

    st.info(
        "Enter an IP address to investigate its recorded honeypot activity."
    )

    investigation_ip = st.text_input(
        "Attacker IP",
        placeholder="Example: 192.168.1.100"
    )

    if investigation_ip:

        matches = df[
            df["attacker_ip"]
            .astype(str)
            .str.strip()
            .str.lower()
            == investigation_ip.strip().lower()
        ]

        if matches.empty:

            st.warning(
                f"No recorded activity found for IP `{investigation_ip}`."
            )

        else:

            st.success(
                f"Found {len(matches)} recorded events for `{investigation_ip}`."
            )

            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.metric("Events", len(matches))

            with c2:
                st.metric(
                    "Usernames",
                    matches["username"]
                    .replace("", pd.NA)
                    .dropna()
                    .nunique()
                )

            with c3:
                st.metric(
                    "Password Attempts",
                    matches["password"]
                    .replace("", pd.NA)
                    .dropna()
                    .count()
                )

            with c4:
                st.metric(
                    "Event Types",
                    matches["event"].nunique()
                )

            st.markdown("### 📋 Evidence")

            st.dataframe(
                matches,
                use_container_width=True,
                hide_index=True
            )

# ============================================================
# LIVE ATTACKS
# ============================================================

elif page == "🔴 Live Attacks":

    st.markdown(
        '<div class="section-title">🔴 Live Attack Monitor</div>',
        unsafe_allow_html=True
    )

    st.caption(
        "Showing the latest events recorded by the honeypot."
    )

    st.dataframe(
        df.head(50),
        use_container_width=True,
        hide_index=True
    )

# ============================================================
# ALERTS
# ============================================================

elif page == "🚨 Alerts":

    st.markdown(
        '<div class="section-title">🚨 Security Alerts</div>',
        unsafe_allow_html=True
    )

    if df.empty:

        st.info("No events available.")

    else:

        counts = df["attacker_ip"].value_counts()

        suspicious = counts[counts >= 5]

        if suspicious.empty:

            st.success("No high-frequency attackers detected.")

        else:

            for ip, count in suspicious.items():

                st.error(
                    f"🚨 High activity detected from `{ip}` — "
                    f"{count} recorded events"
                )

# ============================================================
# THREATS
# ============================================================

elif page == "🛡️ Threats":

    st.markdown(
        '<div class="section-title">🛡️ Threat Intelligence</div>',
        unsafe_allow_html=True
    )

    if df.empty:

        st.info("No threat data available.")

    else:

        threat_table = (
            df.groupby("event")
            .size()
            .reset_index(name="Occurrences")
            .sort_values(
                "Occurrences",
                ascending=False
            )
        )

        st.dataframe(
            threat_table,
            use_container_width=True,
            hide_index=True
        )

# ============================================================
# DEVICES
# ============================================================

elif page == "📡 Devices":

    st.markdown(
        '<div class="section-title">📡 Healthcare IoT Devices</div>',
        unsafe_allow_html=True
    )

    st.info(
        "This honeypot monitors simulated healthcare IoT attack activity."
    )

    device_data = pd.DataFrame(
        [
            ["Medical Gateway", "Online", "Honeypot"],
            ["Patient Monitor", "Protected", "IoT Sensor"],
            ["Infusion Controller", "Protected", "IoT Device"],
            ["Hospital Network Node", "Monitoring", "Network"],
        ],
        columns=["Device", "Status", "Type"]
    )

    st.dataframe(
        device_data,
        use_container_width=True,
        hide_index=True
    )

# ============================================================
# ANALYTICS
# ============================================================

elif page == "📊 Analytics":

    st.markdown(
        '<div class="section-title">📊 Security Analytics</div>',
        unsafe_allow_html=True
    )

    if not df.empty:

        event_counts = (
            df["event"]
            .value_counts()
            .reset_index()
        )

        event_counts.columns = ["Event", "Count"]

        fig = px.bar(
            event_counts,
            x="Event",
            y="Count",
            title="Attack Event Frequency"
        )

        fig.update_layout(
            template="plotly_dark"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

# ============================================================
# DATA SOURCES
# ============================================================

elif page == "🗄️ Data Sources":

    st.markdown(
        '<div class="section-title">🗄️ Data Sources</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
### Honeypot Data Pipeline

**Healthcare IoT Environment**
↓
**Cowrie Honeypot**
↓
**Captured Attacker Activity**
↓
**SQLite Database**
↓
**Streamlit Security Dashboard**

The dashboard reads attack evidence from:

`database/attacks.db`
"""
    )

    st.write("Database:", DB_PATH)

# ============================================================
# ATTACK LOGS
# ============================================================

elif page == "📋 Attack Logs":

    st.markdown(
        '<div class="section-title">📋 Complete Attack Logs</div>',
        unsafe_allow_html=True
    )

    log_search = st.text_input(
        "Filter logs",
        placeholder="IP, username, event..."
    )

    logs = df.copy()

    if log_search:

        q = log_search.lower()

        temp = logs.fillna("").astype(str)

        mask = (
            temp["attacker_ip"].str.lower().str.contains(q, regex=False)
            |
            temp["username"].str.lower().str.contains(q, regex=False)
            |
            temp["event"].str.lower().str.contains(q, regex=False)
        )

        logs = logs[mask]

    st.dataframe(
        logs,
        use_container_width=True,
        hide_index=True
    )

    csv = logs.to_csv(index=False).encode("utf-8")

    st.download_button(
        "📥 Download CSV",
        csv,
        "healthcare_iot_attack_logs.csv",
        "text/csv"
    )

# ============================================================
# REPORTS
# ============================================================

elif page == "📑 Reports":

    st.markdown(
        '<div class="section-title">📑 Security Reports</div>',
        unsafe_allow_html=True
    )

    st.metric(
        "Total Recorded Events",
        len(df)
    )

    st.metric(
        "Unique Attacker IPs",
        df["attacker_ip"].nunique() if not df.empty else 0
    )

    report = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "📥 Export Security Report",
        report,
        "healthcare_iot_security_report.csv",
        "text/csv"
    )

# ============================================================
# SYSTEM STATUS
# ============================================================

elif page == "⚙️ System Status":

    st.markdown(
        '<div class="section-title">⚙️ System Status</div>',
        unsafe_allow_html=True
    )

    st.success("🟢 Streamlit Dashboard — ONLINE")

    if os.path.exists(DB_PATH):
        st.success("🟢 SQLite Database — CONNECTED")
    else:
        st.error("🔴 SQLite Database — NOT FOUND")

    st.info(
        f"Database location: {DB_PATH}"
    )

# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "Healthcare IoT Honeypot | Cowrie + SQLite + Streamlit"
)