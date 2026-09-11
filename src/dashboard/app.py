"""Streamlit dashboard for the Mini-SIEM.

Run with:
    streamlit run src/dashboard/app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Mini-SIEM Dashboard", page_icon="🛡️", layout="wide")

_EVENTS_DEFAULT = "data/output/events.jsonl"
_ALERTS_DEFAULT = "data/output/alerts.jsonl"


@st.cache_data(ttl=5)
def load_jsonl(path: str) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        return pd.DataFrame()
    rows = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return pd.DataFrame(rows)


def header() -> None:
    st.title("🛡️ Mini-SIEM Dashboard")
    st.caption(
        "Python-based log analysis + threat-detection pipeline. "
        "Rules mapped to MITRE ATT&CK, enriched via AbuseIPDB."
    )


def sidebar() -> tuple[str, str]:
    st.sidebar.header("Data sources")
    events_path = st.sidebar.text_input("Events JSONL", _EVENTS_DEFAULT)
    alerts_path = st.sidebar.text_input("Alerts JSONL", _ALERTS_DEFAULT)
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "Generate data by running:\n\n"
        "```bash\npython -m src.main --input data/samples/auth.log --source ssh\n```"
    )
    if st.sidebar.button("Refresh"):
        st.cache_data.clear()
    return events_path, alerts_path


def kpis(events: pd.DataFrame, alerts: pd.DataFrame) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events processed", len(events))
    c2.metric("Alerts fired", len(alerts))
    if not alerts.empty:
        c3.metric("Unique attacker IPs", alerts["source_ip"].nunique())
        c4.metric("Highest severity", alerts["severity"].mode().iat[0].upper() if not alerts["severity"].isna().all() else "-")
    else:
        c3.metric("Unique attacker IPs", 0)
        c4.metric("Highest severity", "-")


def alerts_table(alerts: pd.DataFrame) -> None:
    st.subheader("Alerts")
    if alerts.empty:
        st.info("No alerts yet. Run the pipeline to populate `data/output/alerts.jsonl`.")
        return
    display_cols = [c for c in
                    ["timestamp", "severity", "rule_id", "rule_name", "mitre",
                     "source_ip", "user", "match_count"]
                    if c in alerts.columns]
    st.dataframe(alerts[display_cols].sort_values("timestamp", ascending=False),
                 use_container_width=True, height=320)


def event_charts(events: pd.DataFrame) -> None:
    if events.empty:
        return
    st.subheader("Event volume")
    events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce", utc=True)
    events["minute"] = events["timestamp"].dt.floor("min")
    per_min = events.groupby(["minute", "event_type"]).size().reset_index(name="count")
    fig = px.bar(per_min, x="minute", y="count", color="event_type",
                 title="Events per minute by type")
    st.plotly_chart(fig, use_container_width=True)


def attacker_charts(alerts: pd.DataFrame) -> None:
    if alerts.empty:
        return
    c1, c2 = st.columns(2)
    top_ip = alerts["source_ip"].value_counts().head(10).reset_index()
    top_ip.columns = ["source_ip", "alerts"]
    c1.plotly_chart(
        px.bar(top_ip, x="source_ip", y="alerts", title="Top attacker IPs"),
        use_container_width=True,
    )
    by_rule = alerts["rule_name"].value_counts().reset_index()
    by_rule.columns = ["rule_name", "alerts"]
    c2.plotly_chart(
        px.pie(by_rule, names="rule_name", values="alerts", title="Alerts by rule"),
        use_container_width=True,
    )

    if "mitre" in alerts.columns:
        mitre = alerts["mitre"].value_counts().reset_index()
        mitre.columns = ["mitre_technique", "alerts"]
        st.plotly_chart(
            px.bar(mitre, x="mitre_technique", y="alerts",
                   title="Coverage: alerts by MITRE ATT&CK technique"),
            use_container_width=True,
        )


def main() -> None:
    header()
    events_path, alerts_path = sidebar()
    events = load_jsonl(events_path)
    alerts = load_jsonl(alerts_path)
    kpis(events, alerts)
    alerts_table(alerts)
    event_charts(events)
    attacker_charts(alerts)


if __name__ == "__main__":
    main()
