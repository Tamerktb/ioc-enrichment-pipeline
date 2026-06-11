"""
ipinfo.io Enrichment Tool — IP geolocation and network info.
Works without an API key (rate limited to 50k requests/month).
"""

import time
from .base import BaseTool, ToolSchema


class IPInfoTool(BaseTool):
    """
    Enrich IP addresses with geolocation, ASN, and carrier data via ipinfo.io.
    No API key required for basic lookups.
    """

    name = "ipinfo"
    description = "IP geolocation and network information (ISP, ASN, city, country, coordinates)"

    input_schema = ToolSchema({
        "ioc_type": {
            "type": "string",
            "description": "Type of IOC — must be 'ip'",
            "required": True,
            "enum": ["ip"],
        },
        "ioc_value": {
            "type": "string",
            "description": "The IP address to look up",
            "required": True,
            "pattern": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        },
    })

    def execute(self, ioc_type: str, ioc_value: str, **kwargs) -> dict:
        start = time.time()
        try:
            # Validate only if ip — ipinfo only supports IPs
            if ioc_type != "ip":
                return self.result_error(f"ipinfo only supports 'ip' type, got '{ioc_type}'", time.time() - start)

            response = self._request_with_retry("GET", f"https://ipinfo.io/{ioc_value}/json")

            if response.status_code == 429:
                return self.result_error("Rate limited by ipinfo.io", time.time() - start)

            if response.status_code != 200:
                return self.result_error(
                    f"HTTP {response.status_code}: {response.text[:200]}",
                    time.time() - start
                )

            data = response.json()

            # Structure the result
            enriched = {
                "ip": data.get("ip"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),  # lat,lng
                "org": data.get("org"),  # ASN + ISP name
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
                "hostname": data.get("hostname"),
                "anycast": data.get("anycast", False),
            }

            # Parse ASN
            org = data.get("org", "")
            if "," in org:
                parts = org.split(",", 1)
                enriched["asn"] = parts[0].strip()
                enriched["isp"] = parts[1].strip()
            else:
                enriched["asn"] = org
                enriched["isp"] = org

            # Parse coordinates
            loc = data.get("loc", "")
            if loc and "," in loc:
                parts = loc.split(",")
                enriched["latitude"] = float(parts[0])
                enriched["longitude"] = float(parts[1])

            # High-risk country check
            high_risk_countries = {"RU", "CN", "IR", "KP", "SY", "VE", "CU", "AF"}
            enriched["high_risk_country"] = data.get("country") in high_risk_countries

            return self.result_success(enriched, time.time() - start)

        except Exception as e:
            return self.result_error(str(e), time.time() - start)