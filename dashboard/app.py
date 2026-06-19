import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys
sys.path.append(".")

from storage.database import IncidentDatabase
from ingestion.log_ingester import LogIngester
from ingestion.alert_parser import AlertParser
from agents.soc_agent import SOCAnalystAgent
from reporting.report_generator import ReportGenerator

# Page config
st.set_page_config(
    page_title="SOC Analyst Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .critical { color: #ff4444; font-weight: bold; }
    .high { color: #ff8800; font-weight: bold; }
    .medium { color: #ffcc00; font-weight: bold; }
    .low { color: #44ff44; font-weight: bold; }
    .metric-card {
        background: #1e1e2e;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #7c3aed;
    }
</style>
""", unsafe_allow_html=True)


def load_incidents():
    db = IncidentDatabase()
    return db.get_all_incidents()


def main():
    st.title("🛡️ Autonomous SOC Analyst Agent")
    st.caption("Real-time AI-Powered Security Operations Center")

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Controls")
        if st.button("🔄 Run Analysis on Sample Alerts", type="primary"):
            with st.spinner("Running SOC Agent pipeline..."):
                ingester = LogIngester()
                parser = AlertParser()
                agent = SOCAnalystAgent()
                reporter = ReportGenerator()
                db = IncidentDatabase()

                raw_alerts = ingester.load_all_from_directory()
                parsed = parser.parse_many(raw_alerts)

                for alert in parsed:
                    result = agent.analyze(alert)
                    reporter.generate(result)
                    db.save_incident(result)

            st.success(f"✅ Analyzed {len(parsed)} alerts!")
            st.rerun()

        st.divider()
        st.header("🔗 Quick Links")
        st.markdown("[MITRE ATT&CK](https://attack.mitre.org)")
        st.markdown("[VirusTotal](https://www.virustotal.com)")
        st.markdown("[AbuseIPDB](https://www.abuseipdb.com)")

    # Load data
    incidents = load_incidents()

    if not incidents:
        st.info("No incidents yet. Click 'Run Analysis' in the sidebar.")
        return

    df = pd.DataFrame(incidents)

    # ── KPI Metrics Row ──
    st.header("📊 SOC Dashboard")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Incidents", len(df))
    with col2:
        critical = len(df[df["severity_label"] == "CRITICAL"])
        st.metric("Critical", critical, delta=None)
    with col3:
        true_pos = len(df[df["ai_verdict"] == "TRUE POSITIVE"])
        st.metric("True Positives", true_pos)
    with col4:
        false_pos = len(df[df["ai_verdict"] == "FALSE POSITIVE"])
        st.metric("False Positives", false_pos)

    st.divider()

    # ── Charts Row ──
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        severity_counts = df["severity_label"].value_counts()
        fig = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            color_discrete_map={
                "CRITICAL": "#ff4444",
                "HIGH": "#ff8800",
                "MEDIUM": "#ffcc00",
                "LOW": "#44cc44"
            }
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Incidents by MITRE Tactic")
        tactic_counts = df["mitre_tactic"].value_counts()
        fig2 = px.bar(
            x=tactic_counts.index,
            y=tactic_counts.values,
            color=tactic_counts.values,
            color_continuous_scale="Reds"
        )
        fig2.update_layout(showlegend=False, xaxis_title="", yaxis_title="Count")
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # ── Incident Table ──
    st.subheader("🚨 Incident Feed")

    display_cols = ["alert_id", "event_type", "severity_label",
                    "source_ip", "hostname", "mitre_tactic",
                    "ai_verdict", "created_at"]

    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # ── Incident Detail Viewer ──
    st.subheader("🔍 Incident Detail Viewer")

    alert_ids = df["alert_id"].tolist()
    selected = st.selectbox("Select Incident to View", alert_ids)

    if selected:
        incident = df[df["alert_id"] == selected].iloc[0]

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Alert Information")
            st.json({
                "Alert ID": incident["alert_id"],
                "Event Type": incident["event_type"],
                "Severity": incident["severity_label"],
                "Source IP": incident["source_ip"],
                "Destination IP": incident["destination_ip"],
                "Hostname": incident["hostname"],
                "Timestamp": incident["timestamp"]
            })

        with col2:
            st.markdown("### MITRE ATT&CK & Intel")
            st.json({
                "Tactic": incident["mitre_tactic"],
                "Technique": incident["mitre_technique"],
                "VT Malicious Votes": incident["vt_malicious_votes"],
                "AbuseIPDB Score": str(incident["abuse_confidence_score"]) + "%",
                "AI Verdict": incident["ai_verdict"]
            })

        st.markdown("### 🤖 AI Analyst Assessment")
        st.markdown(incident["ai_analysis"])


if __name__ == "__main__":
    main()