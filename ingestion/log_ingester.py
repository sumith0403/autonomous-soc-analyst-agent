import json
import os
from pathlib import Path


class LogIngester:
    """
    Reads security alerts from multiple sources:
    - JSON files (for testing)
    - Wazuh SIEM API (for production)
    """

    def __init__(self, source="file", alerts_dir="./sample_alerts"):
        self.source = source
        self.alerts_dir = alerts_dir

    def load_from_file(self, filepath: str) -> dict:
        """Load a single alert from a JSON file."""
        with open(filepath, "r") as f:
            alert = json.load(f)
        print(f"[INGESTER] Loaded alert: {alert.get('alert_id')} from {filepath}")
        return alert

    def load_all_from_directory(self) -> list:
        """Load all alerts from the sample_alerts directory."""
        alerts = []
        path = Path(self.alerts_dir)

        for json_file in path.glob("*.json"):
            alert = self.load_from_file(str(json_file))
            alerts.append(alert)

        print(f"[INGESTER] Total alerts loaded: {len(alerts)}")
        return alerts

    def load_from_wazuh(self) -> list:
        """
        Pull alerts from Wazuh API.
        Used in production when Wazuh is running.
        """
        import requests
        from config import WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD

        try:
            # Authenticate
            auth_url = f"{WAZUH_URL}/security/user/authenticate"
            response = requests.post(
                auth_url,
                auth=(WAZUH_USER, WAZUH_PASSWORD),
                verify=False  # For self-signed certs in lab
            )
            token = response.json()["data"]["token"]

            # Fetch alerts
            headers = {"Authorization": f"Bearer {token}"}
            alerts_url = f"{WAZUH_URL}/alerts?limit=10&sort=-timestamp"
            result = requests.get(alerts_url, headers=headers, verify=False)

            alerts = result.json().get("data", {}).get("affected_items", [])
            print(f"[WAZUH] Fetched {len(alerts)} alerts from Wazuh")
            return alerts

        except Exception as e:
            print(f"[WAZUH ERROR] {e}")
            return []