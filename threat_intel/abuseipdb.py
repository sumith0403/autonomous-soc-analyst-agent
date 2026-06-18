import requests
from config import ABUSEIPDB_API_KEY


class AbuseIPDBClient:
    """
    Checks IPs against AbuseIPDB — a community database
    of IPs reported for malicious activity.

    Free API: 1000 requests/day
    Sign up at: https://www.abuseipdb.com/register
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        self.headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        """
        Check if an IP has been reported as abusive.
        confidence_score: 0-100 (100 = definitely malicious)
        """
        url = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": True
        }

        try:
            response = requests.get(url, headers=self.headers, params=params)

            if response.status_code == 200:
                data = response.json()["data"]

                result = {
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "is_tor": data.get("isTor", False),
                    "is_malicious": data.get("abuseConfidenceScore", 0) > 25
                }

                print(f"[AbuseIPDB] IP {ip}: confidence={result['abuse_confidence_score']}%")
                return result
            else:
                return {"ip": ip, "error": f"API error {response.status_code}", "is_malicious": False}

        except Exception as e:
            return {"ip": ip, "error": str(e), "is_malicious": False}