from langchain_openai import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
from ingestion.alert_parser import ParsedAlert
from triage.mitre_mapper import MitreMapper
from threat_intel.virustotal import VirusTotalClient
from threat_intel.abuseipdb import AbuseIPDBClient
from rag.retriever import PlaybookRetriever
from agents.prompts import SOC_ANALYST_SYSTEM_PROMPT, TRIAGE_PROMPT
from config import OPENAI_API_KEY
import json


class SOCAnalystAgent:
    """
    The main AI agent that acts as an autonomous SOC analyst.
    It receives alerts, gathers intelligence, retrieves playbooks,
    and makes decisions like a real Tier 2 SOC analyst would.
    """

    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4o",
            temperature=0,           # 0 = deterministic, consistent responses
            api_key=OPENAI_API_KEY
        )
        self.mitre_mapper = MitreMapper()
        self.vt_client = VirusTotalClient()
        self.abuse_client = AbuseIPDBClient()
        self.retriever = PlaybookRetriever()

        print("[AGENT] SOC Analyst Agent initialized")

    def analyze(self, alert: ParsedAlert) -> dict:
        """
        Full analysis pipeline for a single alert.
        This is the main function that does everything.
        """
        print(f"\n{'='*60}")
        print(f"[AGENT] Analyzing alert: {alert.alert_id}")
        print(f"{'='*60}")

        # Step 1: MITRE mapping
        alert = self.mitre_mapper.map(alert)

        # Step 2: Threat intelligence
        print(f"[AGENT] Gathering threat intelligence...")
        vt_result = self.vt_client.check_ip(alert.source_ip)
        abuse_result = self.abuse_client.check_ip(alert.source_ip)

        threat_intel_summary = (
            f"VirusTotal: {vt_result.get('malicious_votes', 'N/A')} malicious detections, "
            f"Country: {vt_result.get('country', 'Unknown')}\n"
            f"AbuseIPDB: {abuse_result.get('abuse_confidence_score', 'N/A')}% confidence score, "
            f"Reports: {abuse_result.get('total_reports', 'N/A')}, "
            f"ISP: {abuse_result.get('isp', 'Unknown')}"
        )

        # Step 3: Retrieve relevant playbook
        print(f"[AGENT] Retrieving relevant playbook...")
        playbook = self.retriever.retrieve(
            f"{alert.event_type} {alert.rule_description}"
        )

        # Step 4: Build alert details string for the AI
        alert_details = json.dumps({
            "alert_id": alert.alert_id,
            "event_type": alert.event_type,
            "severity": f"{alert.severity} ({alert.severity_label})",
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "hostname": alert.hostname,
            "rule_description": alert.rule_description,
            "timestamp": alert.timestamp,
            "raw_details": alert.raw_alert
        }, indent=2)

        # Step 5: Ask the AI for analysis
        print(f"[AGENT] Requesting AI analysis...")
        prompt = TRIAGE_PROMPT.format(
            alert_details=alert_details,
            threat_intel=threat_intel_summary,
            playbook=playbook[:2000]  # Limit playbook size to save tokens
        )

        messages = [
            SystemMessage(content=SOC_ANALYST_SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ]

        response = self.llm.invoke(messages)
        ai_analysis = response.content

        # Step 6: Package the complete result
        result = {
            "alert": {
                "alert_id": alert.alert_id,
                "event_type": alert.event_type,
                "severity_label": alert.severity_label,
                "severity_score": alert.severity,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "hostname": alert.hostname,
                "timestamp": alert.timestamp,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique": alert.mitre_technique
            },
            "threat_intel": {
                "virustotal": vt_result,
                "abuseipdb": abuse_result
            },
            "ai_analysis": ai_analysis,
            "playbook_used": playbook[:500] + "..."
        }

        print(f"[AGENT] Analysis complete for {alert.alert_id}")
        return result