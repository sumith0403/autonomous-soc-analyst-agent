from ingestion.alert_parser import ParsedAlert


# MITRE ATT&CK mapping table
# Format: event_type → (Tactic, Technique ID, Technique Name)
MITRE_MAPPINGS = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "sub_technique": "T1110.001 - Password Guessing",
        "description": "Adversaries may use brute force to gain access by guessing passwords."
    },
    "malware_detected": {
        "tactic": "Execution",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "sub_technique": "T1204.002 - Malicious File",
        "description": "Adversary relies on user executing malicious code."
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "sub_technique": "T1041 - Exfiltration Over C2 Channel",
        "description": "Adversary steals data by exfiltrating it over the C2 channel."
    },
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "sub_technique": "T1021.001 - Remote Desktop Protocol",
        "description": "Adversary uses remote services to move through the network."
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "sub_technique": "T1068",
        "description": "Adversary exploits vulnerability to gain higher privileges."
    },
    "phishing": {
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "sub_technique": "T1566.001 - Spearphishing Attachment",
        "description": "Adversary sends phishing emails with malicious attachments."
    },
    "c2_communication": {
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "sub_technique": "T1071.001 - Web Protocols",
        "description": "Adversary uses web protocols to communicate with C2."
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "sub_technique": "T1046",
        "description": "Adversary scans network to identify open ports and services."
    }
}


class MitreMapper:
    """
    Maps parsed alerts to MITRE ATT&CK tactics and techniques.
    This is what makes your project look EXTREMELY professional
    to recruiters — it shows you understand real threat modeling.
    """

    def map(self, alert: ParsedAlert) -> ParsedAlert:
        """Add MITRE ATT&CK mapping to an alert."""

        event_type = alert.event_type.lower()
        mapping = MITRE_MAPPINGS.get(event_type)

        if mapping:
            alert.mitre_tactic = mapping["tactic"]
            alert.mitre_technique = f"{mapping['technique_id']} - {mapping['technique_name']}"
            print(f"[MITRE] {alert.alert_id} → {alert.mitre_tactic} | {alert.mitre_technique}")
        else:
            alert.mitre_tactic = "Unknown"
            alert.mitre_technique = "Unmapped - Manual Review Required"
            print(f"[MITRE] {alert.alert_id} → No mapping found for '{event_type}'")

        return alert

    def get_full_mapping(self, event_type: str) -> dict:
        """Return the full MITRE mapping for display in reports/dashboard."""
        return MITRE_MAPPINGS.get(event_type.lower(), {})