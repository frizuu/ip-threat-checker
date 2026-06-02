import requests
from config import Config


class AbuseIPDBClient:

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    @staticmethod
    def check_ip(ip: str) -> dict:
        headers = {
            "Key": Config.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(
                AbuseIPDBClient.BASE_URL,
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}"
                }

            data = response.json()["data"]

            return {
                "success": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "-"),
                "isp": data.get("isp", "-"),
                "domain": data.get("domain", "-"),
                "is_whitelisted": data.get("isWhitelisted", False)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
