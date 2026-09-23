"""
THREVIA — Threat Recognition, Evaluation & Visualization using Intelligent Analytics
Streamlit dashboard: reads live data from MongoDB and renders threat analytics.
"""

import os
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError

# ─────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="THREVIA",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Host port published by docker-compose (container 27017 -> host 27018).
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018/")
DB_NAME = "threvia"

PLOTLY_DARK_LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
)

SEVERITY_COLORS = {"Critical": "#e63946", "High": "#f4a261", "Medium": "#e9c46a"}
SEVERITY_ORDER = ["Critical", "High", "Medium"]

GRAPH_EXPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "backend", "graph", "graph_export.html"
)


# ─────────────────────────────────────────────────────────────────────────
# MONGODB CONNECTION + QUERY FUNCTIONS  (all reads live here, top of file)
# ─────────────────────────────────────────────────────────────────────────

@st.cache_resource
def get_client():
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)


def get_db():
    client = get_client()
    return client[DB_NAME]


@st.cache_data(ttl=30)
def fetch_graph_nodes():
    try:
        db = get_db()
        docs = list(db.graph_nodes.find({}, {"_id": 0}))
        return pd.DataFrame(docs)
    except PyMongoError as e:
        st.error(f"MongoDB error while fetching graph_nodes: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=30)
def fetch_graph_edges():
    try:
        db = get_db()
        docs = list(db.graph_edges.find({}, {"_id": 0}))
        return pd.DataFrame(docs)
    except PyMongoError as e:
        st.error(f"MongoDB error while fetching graph_edges: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=30)
def fetch_graph_communities():
    try:
        db = get_db()
        docs = list(db.graph_communities.find({}, {"_id": 0}))
        return pd.DataFrame(docs)
    except PyMongoError as e:
        st.error(f"MongoDB error while fetching graph_communities: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=30)
def fetch_graph_meta():
    try:
        db = get_db()
        doc = db.graph_meta.find_one({}, {"_id": 0})
        return doc or {}
    except PyMongoError as e:
        st.error(f"MongoDB error while fetching graph_meta: {e}")
        return {}


@st.cache_data(ttl=30)
def fetch_stream_alerts():
    try:
        db = get_db()
        docs = list(db.stream_alerts.find({}).sort("created_at", DESCENDING))
        df = pd.DataFrame(docs)
        if not df.empty:
            df.drop(columns=["_id"], errors="ignore", inplace=True)
            df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
        return df
    except PyMongoError as e:
        st.error(f"MongoDB error while fetching stream_alerts: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=30)
def fetch_bloom_hits():
    try:
        db = get_db()
        docs = list(db.bloom_hits.find({}).sort("created_at", DESCENDING))
        df = pd.DataFrame(docs)
        if not df.empty:
            df.drop(columns=["_id"], errors="ignore", inplace=True)
            df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
        return df
    except PyMongoError as e:
        st.error(f"MongoDB error while fetching bloom_hits: {e}")
        return pd.DataFrame()


# ─────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────

def empty_state(label: str):
    st.warning("No data yet — run Phase 4 and Phase 5 first.")


def apply_time_filter(df: pd.DataFrame, start, end, col="created_at"):
    if df.empty or col not in df.columns:
        return df
    mask = (df[col] >= pd.Timestamp(start)) & (df[col] <= pd.Timestamp(end) + timedelta(days=1))
    return df.loc[mask]


def apply_severity_filter(df: pd.DataFrame, severities):
    if df.empty or not severities or "severity" not in df.columns:
        return df
    return df[df["severity"].isin(severities)]


def apply_ip_filter(df: pd.DataFrame, ip_query, ip_cols):
    if df.empty or not ip_query:
        return df
    cols_present = [c for c in ip_cols if c in df.columns]
    if not cols_present:
        return df
    mask = False
    for c in cols_present:
        mask = mask | df[c].astype(str).str.contains(ip_query, case=False, na=False)
    return df[mask]


def apply_attack_cat_filter(df: pd.DataFrame, cats, col="attack_cats"):
    if df.empty or not cats or col not in df.columns:
        return df

    def has_overlap(val):
        if isinstance(val, list):
            return any(c in val for c in cats)
        return val in cats

    return df[df[col].apply(has_overlap)]


def style_severity(df: pd.DataFrame, col="Severity"):
    def color_cell(val):
        color = SEVERITY_COLORS.get(val, None)
        if color:
            return f"background-color: {color}; color: #0d1117; font-weight: 600;"
        return ""
    return df.style.applymap(color_cell, subset=[col]) if col in df.columns else df.style


def style_attacker_rows(df: pd.DataFrame, flag_col="Attacker"):
    def highlight_row(row):
        if row.get(flag_col, False) is True or row.get(flag_col, "") == True:  # noqa: E712
            return ["background-color: rgba(230, 57, 70, 0.35);"] * len(row)
        return [""] * len(row)
    return df.style.apply(highlight_row, axis=1)


# ─────────────────────────────────────────────────────────────────────────
# SIDEBAR — FILTERS
# ─────────────────────────────────────────────────────────────────────────

st.sidebar.markdown("## 🛡️ THREVIA Controls")

default_end = datetime.utcnow().date()
default_start = default_end - timedelta(days=7)

date_range = st.sidebar.date_input(
    "Time range",
    value=(default_start, default_end),
    help="Filters Anomaly Alerts and Bloom Filter Hits by creation time.",
)
if isinstance(date_range, tuple) and len(date_range) == 2:
    range_start, range_end = date_range
else:
    range_start, range_end = default_start, default_end

_nodes_for_filters = fetch_graph_nodes()
all_attack_cats = sorted(
    {c for cats in _nodes_for_filters.get("attack_cats", pd.Series(dtype=object)) for c in (cats or [])}
) if not _nodes_for_filters.empty else []

selected_attack_cats = st.sidebar.multiselect("Attack type", options=all_attack_cats)

selected_severities = st.sidebar.multiselect(
    "Severity", options=SEVERITY_ORDER, default=[]
)

ip_search = st.sidebar.text_input("IP search", placeholder="e.g. 175.45.176.0")

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("THREVIA · Big Data Cybersecurity Analytics")


# ─────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────

st.markdown(
    "<h1 style='margin-bottom:0;'>🛡️ THREVIA</h1>"
    "<p style='color:#8b949e; margin-top:0;'>Threat Recognition, Evaluation & Visualization using Intelligent Analytics</p>",
    unsafe_allow_html=True,
)

# Pre-load core datasets once
graph_nodes_df = fetch_graph_nodes()
graph_edges_df = fetch_graph_edges()
graph_communities_df = fetch_graph_communities()
graph_meta = fetch_graph_meta()
stream_alerts_df = fetch_stream_alerts()
bloom_hits_df = fetch_bloom_hits()

# Apply sidebar filters to time-series collections
filtered_alerts_df = apply_time_filter(stream_alerts_df, range_start, range_end)
filtered_alerts_df = apply_severity_filter(filtered_alerts_df, selected_severities)
filtered_alerts_df = apply_ip_filter(filtered_alerts_df, ip_search, ["src_ip"])

filtered_bloom_df = apply_time_filter(bloom_hits_df, range_start, range_end)
filtered_bloom_df = apply_ip_filter(filtered_bloom_df, ip_search, ["src_ip", "dst_ip"])

filtered_nodes_df = apply_attack_cat_filter(graph_nodes_df, selected_attack_cats)
filtered_nodes_df = apply_ip_filter(filtered_nodes_df, ip_search, ["ip"])


tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["📊 Overview", "🚨 Suspicious IPs", "⚡ Anomaly Alerts", "🕸️ Network Graph", "🧪 Bloom Filter Hits"]
)

# ─────────────────────────────────────────────────────────────────────────
# TAB 1 — OVERVIEW
# ─────────────────────────────────────────────────────────────────────────
with tab1:
    col1, col2, col3, col4 = st.columns(4)

    total_nodes = len(graph_nodes_df) if not graph_nodes_df.empty else 0
    total_attackers = (
        int(graph_nodes_df["is_attacker"].sum()) if "is_attacker" in graph_nodes_df.columns else 0
    )
    active_alerts = len(filtered_alerts_df)
    bloom_hit_count = len(filtered_bloom_df)

    col1.metric("Total Nodes", f"{total_nodes:,}")
    col2.metric("Total Attacker IPs", f"{total_attackers:,}")
    col3.metric("Active Alerts", f"{active_alerts:,}")
    col4.metric("Bloom Hits", f"{bloom_hit_count:,}")

    st.markdown("### Alerts by Severity")
    if filtered_alerts_df.empty:
        empty_state("stream_alerts")
    else:
        sev_counts = (
            filtered_alerts_df["severity"]
            .value_counts()
            .reindex(SEVERITY_ORDER)
            .fillna(0)
            .reset_index()
        )
        sev_counts.columns = ["Severity", "Count"]
        fig = px.bar(
            sev_counts,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map=SEVERITY_COLORS,
            title="Alerts by Severity",
        )
        fig.update_layout(**PLOTLY_DARK_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Alert Volume Over Time")
    if filtered_alerts_df.empty:
        empty_state("stream_alerts")
    else:
        hourly = filtered_alerts_df.copy()
        hourly["hour"] = hourly["created_at"].dt.floor("h")
        hourly_counts = (
            hourly.groupby(["hour", "severity"]).size().reset_index(name="count")
        )
        fig = px.line(
            hourly_counts,
            x="hour",
            y="count",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            markers=True,
            title="Alert Volume Over Time",
            labels={"hour": "Time", "count": "Alert Count", "severity": "Severity"},
        )
        fig.update_layout(**PLOTLY_DARK_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────
# TAB 2 — SUSPICIOUS IPS
# ─────────────────────────────────────────────────────────────────────────
with tab2:
    st.markdown("### Top 20 IPs by Danger Score")
    top_nodes = graph_meta.get("top_nodes", [])
    if not top_nodes:
        empty_state("graph_meta")
    else:
        top_df = pd.DataFrame(top_nodes).sort_values("danger_score", ascending=False).head(20)
        top_df["bar_color"] = top_df["is_attacker"].apply(
            lambda x: "#e63946" if x else "#4a90d9"
        )
        fig = go.Figure(
            go.Bar(
                x=top_df["danger_score"],
                y=top_df["ip"],
                orientation="h",
                marker_color=top_df["bar_color"],
            )
        )
        fig.update_layout(
            title="Top 20 IPs by Danger Score",
            yaxis=dict(autorange="reversed"),
            xaxis_title="Danger Score",
            **PLOTLY_DARK_LAYOUT,
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### All Nodes")
    if filtered_nodes_df.empty:
        empty_state("graph_nodes")
    else:
        display_df = filtered_nodes_df.copy().sort_values("pagerank", ascending=False)
        display_df = display_df.rename(
            columns={
                "ip": "IP",
                "pagerank": "PageRank",
                "danger_score": "Danger Score",
                "out_degree": "Out-Degree",
                "in_degree": "In-Degree",
                "total_flows": "Flows",
                "is_attacker": "Attacker",
                "community_id": "Community",
                "attack_cats": "Attack Categories",
            }
        )
        cols = [
            "IP", "PageRank", "Danger Score", "Out-Degree", "In-Degree",
            "Flows", "Attacker", "Community", "Attack Categories",
        ]
        cols_present = [c for c in cols if c in display_df.columns]
        display_df = display_df[cols_present]
        st.dataframe(
            style_attacker_rows(display_df, flag_col="Attacker"),
            use_container_width=True,
            height=500,
        )


# ─────────────────────────────────────────────────────────────────────────
# TAB 3 — ANOMALY ALERTS
# ─────────────────────────────────────────────────────────────────────────
with tab3:
    st.markdown("### Alerts")
    if filtered_alerts_df.empty:
        empty_state("stream_alerts")
    else:
        alerts_display = filtered_alerts_df.copy()
        alerts_display["Window"] = (
            alerts_display["window_start"].astype(str) + " → " + alerts_display["window_end"].astype(str)
        )
        alerts_display = alerts_display.rename(
            columns={
                "created_at": "Time",
                "src_ip": "Source IP",
                "severity": "Severity",
                "connection_count": "Connections",
                "total_bytes": "Bytes",
                "attack_label": "Attack Label",
            }
        )
        cols = ["Time", "Source IP", "Severity", "Connections", "Bytes", "Attack Label", "Window"]
        cols_present = [c for c in cols if c in alerts_display.columns]
        alerts_display = alerts_display[cols_present].sort_values("Time", ascending=False)
        st.dataframe(
            style_severity(alerts_display, col="Severity"),
            use_container_width=True,
            height=450,
        )

        st.markdown("### Connections per Alert")
        plot_df = filtered_alerts_df.copy()
        max_bytes = plot_df["total_bytes"].max() if plot_df["total_bytes"].max() > 0 else 1
        plot_df["size_norm"] = (plot_df["total_bytes"] / max_bytes) * 40 + 5
        fig = px.scatter(
            plot_df,
            x="window_start",
            y="connection_count",
            size="size_norm",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            hover_data=plot_df.columns,
            title="Connections per Alert",
            labels={"window_start": "Window Start", "connection_count": "Connections"},
        )
        fig.update_layout(**PLOTLY_DARK_LAYOUT)
        st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────
# TAB 4 — NETWORK GRAPH
# ─────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("### Network Relationship Graph")
    if os.path.exists(GRAPH_EXPORT_PATH):
        with open(GRAPH_EXPORT_PATH, "r", encoding="utf-8") as f:
            html_content = f.read()
        st.components.v1.html(html_content, height=750, scrolling=False)
    else:
        st.warning("No data yet — run Phase 4 and Phase 5 first.")

    left, right = st.columns(2)

    with left:
        st.markdown("#### Communities")
        if graph_communities_df.empty:
            empty_state("graph_communities")
        else:
            comm_display = graph_communities_df.copy().sort_values("size", ascending=False)
            comm_display = comm_display.rename(
                columns={
                    "community_id": "Community ID",
                    "size": "Size",
                    "attacker_count": "Attackers",
                    "attack_cats": "Attack Categories",
                    "is_malicious": "Malicious",
                }
            )
            cols = ["Community ID", "Size", "Attackers", "Attack Categories", "Malicious"]
            cols_present = [c for c in cols if c in comm_display.columns]
            st.dataframe(comm_display[cols_present], use_container_width=True, height=400)

    with right:
        st.markdown("#### Malicious Edges")
        if graph_edges_df.empty:
            empty_state("graph_edges")
        else:
            attack_edges = graph_edges_df[graph_edges_df["has_attack"] == True]  # noqa: E712
            if attack_edges.empty:
                empty_state("graph_edges")
            else:
                attack_edges = attack_edges.sort_values("weight", ascending=False).copy()
                attack_edges["Protocols"] = attack_edges["proto_counts"].apply(
                    lambda d: ", ".join(f"{k}:{v}" for k, v in d.items()) if isinstance(d, dict) else ""
                )
                attack_edges = attack_edges.rename(
                    columns={
                        "src_ip": "Source IP",
                        "dst_ip": "Dest IP",
                        "weight": "Flows",
                        "total_bytes": "Bytes",
                        "attack_cats": "Attack Categories",
                    }
                )
                cols = ["Source IP", "Dest IP", "Flows", "Bytes", "Attack Categories", "Protocols"]
                cols_present = [c for c in cols if c in attack_edges.columns]
                st.dataframe(attack_edges[cols_present], use_container_width=True, height=400)


# ─────────────────────────────────────────────────────────────────────────
# TAB 5 — BLOOM FILTER HITS
# ─────────────────────────────────────────────────────────────────────────
with tab5:
    st.markdown("### Bloom Filter Hits")
    if filtered_bloom_df.empty:
        empty_state("bloom_hits")
    else:
        bloom_display = filtered_bloom_df.copy().rename(
            columns={
                "created_at": "Time",
                "src_ip": "Source IP",
                "dst_ip": "Dest IP",
                "proto": "Protocol",
                "service": "Service",
                "attack_cat": "Attack Category",
                "label": "Label",
            }
        )
        cols = ["Time", "Source IP", "Dest IP", "Protocol", "Service", "Attack Category", "Label"]
        cols_present = [c for c in cols if c in bloom_display.columns]
        bloom_display = bloom_display[cols_present].sort_values("Time", ascending=False)
        st.dataframe(bloom_display, use_container_width=True, height=400)

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("#### Bloom Hits by Attack Category")
            cat_counts = filtered_bloom_df["attack_cat"].value_counts().reset_index()
            cat_counts.columns = ["Attack Category", "Count"]
            fig = px.pie(
                cat_counts,
                names="Attack Category",
                values="Count",
                title="Bloom Hits by Attack Category",
                hole=0.35,
            )
            fig.update_layout(**PLOTLY_DARK_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)

        with col_b:
            st.markdown("#### Top Attacker IPs by Bloom Hit Count")
            top_ips = filtered_bloom_df["src_ip"].value_counts().head(10).reset_index()
            top_ips.columns = ["Source IP", "Hit Count"]
            fig = px.bar(
                top_ips,
                x="Source IP",
                y="Hit Count",
                title="Top Attacker IPs by Bloom Hit Count",
                color_discrete_sequence=["#e63946"],
            )
            fig.update_layout(**PLOTLY_DARK_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)
