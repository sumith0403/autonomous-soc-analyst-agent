import requests
import json
from config import SLACK_WEBHOOK_URL


class SlackAlerter:
    """
    Sends real-time alerts to a Slack channel.
    SOC teams use Slack/Teams for instant notifications.

    Setup: Create a Slack Incoming Webhook at:
    https://api.slack.com/messaging/webhooks
    """

    def send_alert(self, analysis_result: dict) -> bool:
        """Send a formatted security alert to Slack."""

        if not SLACK_WEBHOOK_URL:
            print("[SLACK] No webhook URL configured, skipping")
            return False

        alert = analysis_result["alert"]
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(alert["severity_label"], "⚪")

        message = {
            "text": f"{severity_emoji} *SOC ALERT: {alert['severity_label']}*",
            "attachments": [{
                "color": {"CRITICAL": "danger", "HIGH": "warning",
                          "MEDIUM": "warning", "LOW": "good"}.get(
                              alert["severity_label"], "default"),
                "fields": [
                    {"title": "Alert ID", "value": alert["alert_id"], "short": True},
                    {"title": "Event Type", "value": alert["event_type"], "short": True},
                    {"title": "Source IP", "value": alert["source_ip"], "short": True},
                    {"title": "Hostname", "value": alert["hostname"], "short": True},
                    {"title": "MITRE Tactic", "value": alert.get("mitre_tactic", "Unknown"), "short": True},
                    {"title": "MITRE Technique", "value": alert.get("mitre_technique", "Unknown"), "short": True},
                ],
                "footer": "Autonomous SOC Agent v1.0"
            }]
        }

        try:
            response = requests.post(
                SLACK_WEBHOOK_URL,
                data=json.dumps(message),
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                print(f"[SLACK] Alert sent for {alert['alert_id']}")
                return True
            else:
                print(f"[SLACK] Failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[SLACK ERROR] {e}")
            return False