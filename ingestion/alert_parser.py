from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ParsedAlert:
    """
    A clean, standardized alert object.
    No matter where the alert comes from (Wazuh, file, API),
    it gets converted to this standard format.
    """
    alert_id: str
    timestamp: str
    event_type: str
    severity: int
    severity_label: str          # CRITICAL / HIGH / MEDIUM / LOW
    source_ip: str
    destination_ip: str
    destination_port: Optional[int]
    protocol: str
    rule_description: str
    hostname: str
    raw_alert: dict = field(default_factory=dict)

    # Enriched fields (filled in later by other modules)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    threat_intel: Optional[dict] = None
    recommended_playbook: Optional[str] = None
    analyst_notes: Optional[str] = None


class AlertParser:
    """
    Converts raw alert dictionaries into clean ParsedAlert objects.
    Think of this as the 'intake desk' at a hospital —
    it takes whatever format the alert arrives in and
    standardizes it for the rest of the system.
    """

    SEVERITY_LABELS = {
        (15, 100): "CRITICAL",
        (10, 14):  "HIGH",
        (5, 9):    "MEDIUM",
        (0, 4):    "LOW"
    }

    def get_severity_label(self, score: int) -> str:
        for (low, high), label in self.SEVERITY_LABELS.items():
            if low <= score <= high:
                return label
        return "UNKNOWN"

    def parse(self, raw_alert: dict) -> ParsedAlert:
        """Parse a single raw alert dict into a ParsedAlert."""

        severity_score = raw_alert.get("severity", 0)

        parsed = ParsedAlert(
            alert_id=raw_alert.get("alert_id", f"ALT-{datetime.now().timestamp()}"),
            timestamp=raw_alert.get("timestamp", datetime.now().isoformat()),
            event_type=raw_alert.get("event_type", "unknown"),
            severity=severity_score,
            severity_label=self.get_severity_label(severity_score),
            source_ip=raw_alert.get("source_ip", "0.0.0.0"),
            destination_ip=raw_alert.get("destination_ip", "0.0.0.0"),
            destination_port=raw_alert.get("destination_port"),
            protocol=raw_alert.get("protocol", "UNKNOWN"),
            rule_description=raw_alert.get("rule_description", "No description"),
            hostname=raw_alert.get("hostname", "unknown-host"),
            raw_alert=raw_alert
        )

        print(f"[PARSER] Alert {parsed.alert_id} | {parsed.severity_label} | {parsed.event_type}")
        return parsed

    def parse_many(self, raw_alerts: list) -> list:
        """Parse a list of raw alerts."""
        return [self.parse(alert) for alert in raw_alerts]