"""
AbuseIPDB Enrichment Tool — IP reputation data from AbuseIPDB.
Requires ABUSEIPDB_API_KEY environment variable.
"""

import time
import os
from .base import BaseTool, ToolSchema


class AbuseIPDBTool(BaseTool):
    """
    Enrich IP addresses with abuse reports, confidence score, and categories.
    Requires a free API key from https://www.abuseipdb.com/api
    """

    name = "abuseipdb"
    description = "IP abuse reputation — report count, confidence score, abuse categories"

    input_schema = ToolSchema({
        "ioc_type": {
            "type": "string",
            "description": "Type of IOC — must be 'ip'",
            "required": True,
            "enum": ["ip"],
        },
        "ioc_value": {
            "type": "string",
            "description": "The IP address to check",
            "required": True,
        },
        "max_age_in_days": {
            "type": "integer",
            "description": "Max age of reports to consider (default: 30)",
            "required": False,
            "default": 30,
        },
    })

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self._session.headers.update({
            "Key": self.api_key,
            "Content-Type": "application/json",
        })
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def execute(self, ioc_type: str, ioc_value: str, **kwargs) -> dict:
        start = time.time()

        if not self.api_key:
            return self.result_error(
                "ABUSEIPDB_API_KEY not set. Get a free key at https://www.abuseipdb.com/api",
                time.time() - start
            )

        if ioc_type != "ip":
            return self.result_error(f"AbuseIPDB only supports 'ip' type, got '{ioc_type}'", time.time() - start)

        try:
            max_age = kwargs.get("max_age_in_days", 30)
            params = {
                "ipAddress": ioc_value,
                "maxAgeInDays": max_age,
                "verbose": True,
            }

            response = self._request_with_retry(
                "GET",
                f"{self.base_url}/check",
                params=params,
            )

            if response.status_code == 429:
                return self.result_error("Rate limited by AbuseIPDB", time.time() - start)

            if response.status_code == 401:
                return self.result_error("Invalid AbuseIPDB API key", time.time() - start)

            if response.status_code != 200:
                return self.result_error(
                    f"HTTP {response.status_code}: {response.text[:200]}",
                    time.time() - start
                )

            data = response.json().get("data", {})

            # Structure the result
            enriched = {
                "ip": data.get("ipAddress"),
                "is_public": data.get("isPublic"),
                "ip_version": data.get("ipVersion"),
                "is_whitelisted": data.get("isWhitelisted"),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "country_name": data.get("countryName"),
                "domain": data.get("domain"),
                "hostname": data.get("hostnames", []),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "reports": data.get("reports", []),
            }

            # Categorize the confidence score
            score = enriched["abuse_confidence_score"]
            if score >= 75:
                enriched["severity"] = "high"
            elif score >= 40:
                enriched["severity"] = "medium"
            elif score > 0:
                enriched["severity"] = "low"
            else:
                enriched["severity"] = "none"

            return self.result_success(enriched, time.time() - start)

        except Exception as e:
            return self.result_error(str(e), time.time() - start)