"""
AUTONOMOUS SOC ANALYST AGENT
=============================
Main entry point. Runs the full pipeline:
1. Ingest alerts
2. Parse alerts
3. Run AI analysis (MITRE + Threat Intel + Playbook + AI)
4. Generate reports
5. Store incidents
6. Trigger autonomous responses
"""

from ingestion.log_ingester import LogIngester
from ingestion.alert_parser import AlertParser
from agents.soc_agent import SOCAnalystAgent
from reporting.report_generator import ReportGenerator
from storage.database import IncidentDatabase
from response.slack_alert import SlackAlerter
from response.block_ip import IPBlocker
from config import SEVERITY_CRITICAL, SEVERITY_HIGH


def should_auto_respond(analysis_result: dict) -> bool:
    """Decide if autonomous response should be triggered."""
    severity = analysis_result["alert"]["severity_score"]
    ai_text = analysis_result["ai_analysis"].upper()
    abuse_score = analysis_result["threat_intel"]["abuseipdb"].get(
        "abuse_confidence_score", 0)

    return (
        severity >= SEVERITY_HIGH and
        "TRUE POSITIVE" in ai_text and
        abuse_score > 50
    )


def run_pipeline(alert_source="file"):
    """Run the complete SOC analyst pipeline."""

    print("\n" + "="*60)
    print("  🛡️  AUTONOMOUS SOC ANALYST AGENT STARTING")
    print("="*60 + "\n")

    # Initialize all components
    ingester = LogIngester(source=alert_source)
    parser = AlertParser()
    agent = SOCAnalystAgent()
    reporter = ReportGenerator()
    database = IncidentDatabase()
    slack = SlackAlerter()
    blocker = IPBlocker(dry_run=True)  # Set dry_run=False in production

    # Step 1: Load alerts
    print("[PIPELINE] Step 1: Loading alerts...")
    raw_alerts = ingester.load_all_from_directory()

    if not raw_alerts:
        print("[PIPELINE] No alerts found. Exiting.")
        return

    # Step 2: Parse alerts
    print("\n[PIPELINE] Step 2: Parsing alerts...")
    parsed_alerts = parser.parse_many(raw_alerts)

    # Step 3: Analyze each alert
    results = []
    for alert in parsed_alerts:
        print(f"\n[PIPELINE] Step 3: Analyzing {alert.alert_id}...")

        # Run full AI analysis
        result = agent.analyze(alert)
        results.append(result)

        # Step 4: Generate report
        print(f"[PIPELINE] Step 4: Generating report...")
        reporter.generate(result)
        reporter.save_as_json(result)

        # Step 5: Save to database
        print(f"[PIPELINE] Step 5: Saving to database...")
        database.save_incident(result)

        # Step 6: Autonomous response
        print(f"[PIPELINE] Step 6: Checking autonomous response...")
        if should_auto_respond(result):
            print(f"[RESPONSE] Triggering autonomous response!")
            slack.send_alert(result)
            blocker.block_ip(
                result["alert"]["source_ip"],
                reason=result["alert"]["event_type"]
            )
        else:
            print(f"[RESPONSE] No autonomous response triggered")

    # Summary
    print("\n" + "="*60)
    print(f"  ✅ PIPELINE COMPLETE")
    print(f"  Alerts Processed: {len(results)}")
    print(f"  Reports saved to: ./reports/")
    print(f"  Run dashboard: streamlit run dashboard/app.py")
    print("="*60 + "\n")

    return results


if __name__ == "__main__":
    run_pipeline()