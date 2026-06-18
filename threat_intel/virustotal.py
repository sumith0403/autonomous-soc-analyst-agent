import requests
from config import VIRUSTOTAL_API_KEY


class VirusTotalClient:
    """
    Queries VirusTotal to check if IPs, URLs, or file hashes
    are known to be malicious.

    Free API: 4 requests/minute, 500/day
    Sign up at: https://www.virustotal.com/gui/join-us
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    def check_ip(self, ip: str) -> dict:
        """Check if an IP is malicious."""
        url = f"{self.BASE_URL}/ip_addresses/{ip}"

        try:
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]

                result = {
                    "ip": ip,
                    "malicious_votes": stats.get("malicious", 0),
                    "suspicious_votes": stats.get("suspicious", 0),
                    "harmless_votes": stats.get("harmless", 0),
                    "total_engines": sum(stats.values()),
                    "reputation": data["data"]["attributes"].get("reputation", 0),
                    "country": data["data"]["attributes"].get("country", "Unknown"),
                    "is_malicious": stats.get("malicious", 0) > 2
                }

                print(f"[VT] IP {ip}: {result['malicious_votes']} malicious detections")
                return result

            elif response.status_code == 404:
                return {"ip": ip, "error": "Not found in VirusTotal", "is_malicious": False}
            else:
                return {"ip": ip, "error": f"API error {response.status_code}", "is_malicious": False}

        except Exception as e:
            return {"ip": ip, "error": str(e), "is_malicious": False}

    def check_hash(self, file_hash: str) -> dict:
        """Check if a file hash is malicious."""
        url = f"{self.BASE_URL}/files/{file_hash}"

        try:
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]

                return {
                    "hash": file_hash,
                    "malicious_votes": stats.get("malicious", 0),
                    "file_type": data["data"]["attributes"].get("type_description", "Unknown"),
                    "file_name": data["data"]["attributes"].get("meaningful_name", "Unknown"),
                    "is_malicious": stats.get("malicious", 0) > 2
                }
            else:
                return {"hash": file_hash, "error": "Not found", "is_malicious": False}

        except Exception as e:
            return {"hash": file_hash, "error": str(e), "is_malicious": False}