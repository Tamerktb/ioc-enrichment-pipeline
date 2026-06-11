"""
VirusTotal Enrichment Tool — Multi-engine malware detection and threat intel.
Requires VIRUSTOTAL_API_KEY environment variable.
"""

import time
import os
from .base import BaseTool, ToolSchema


class VirusTotalTool(BaseTool):
    """
    Enrich IOCs (IPs, domains, hashes, URLs) with VirusTotal detection results.
    Requires a free API key from https://www.virustotal.com/gui/my-apikey
    Free tier: 4 requests/min, 500 requests/day.
    """

    name = "virustotal"
    description = "Multi-engine malware detection — scan IPs, domains, hashes, and URLs across 70+ antivirus engines"

    input_schema = ToolSchema({
        "ioc_type": {
            "type": "string",
            "description": "Type of IOC: ip, domain, hash, or url",
            "required": True,
            "enum": ["ip", "domain", "hash", "url"],
        },
        "ioc_value": {
            "type": "string",
            "description": "The IOC value to scan",
            "required": True,
        },
    })

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._session.headers.update({
            "x-apikey": self.api_key,
        })
        self.base_url = "https://www.virustotal.com/api/v3"

    def _get_endpoint(self, ioc_type: str, ioc_value: str) -> str:
        """Get the correct API endpoint for the IOC type."""
        endpoint_map = {
            "ip": f"{self.base_url}/ip_addresses/{ioc_value}",
            "domain": f"{self.base_url}/domains/{ioc_value}",
            "hash": f"{self.base_url}/files/{ioc_value}",
            "url": f"{self.base_url}/urls/{ioc_value}",
        }
        return endpoint_map.get(ioc_type, "")

    def execute(self, ioc_type: str, ioc_value: str, **kwargs) -> dict:
        start = time.time()

        if not self.api_key:
            return self.result_error(
                "VIRUSTOTAL_API_KEY not set. Get a free key at https://www.virustotal.com/gui/my-apikey",
                time.time() - start
            )

        try:
            endpoint = self._get_endpoint(ioc_type, ioc_value)
            if not endpoint:
                return self.result_error(f"VirusTotal does not support '{ioc_type}' type", time.time() - start)

            response = self._request_with_retry("GET", endpoint)

            if response.status_code == 429:
                return self.result_error("Rate limited by VirusTotal (free tier: 4 req/min)", time.time() - start)

            if response.status_code == 401:
                return self.result_error("Invalid VirusTotal API key", time.time() - start)

            if response.status_code == 404:
                return self.result_error(f"IOC not found in VirusTotal database", time.time() - start)

            if response.status_code != 200:
                return self.result_error(
                    f"HTTP {response.status_code}: {response.text[:200]}",
                    time.time() - start
                )

            data = response.json().get("data", {})
            attributes = data.get("attributes", {})

            # Parse last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_engines = malicious + suspicious + harmless + undetected

            # Get meaningful results from engines that detected it
            detected_results = []
            analysis_results = attributes.get("last_analysis_results", {})
            for engine, result in analysis_results.items():
                if result.get("category") in ("malicious", "suspicious"):
                    detected_results.append({
                        "engine": engine,
                        "category": result.get("category"),
                        "result": result.get("result"),
                    })

            # Structure the result
            enriched = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines,
                "detection_ratio": f"{malicious}/{total_engines}" if total_engines > 0 else "0/0",
                "detected_by": [r for r in detected_results if r["category"] == "malicious"],
                "suspected_by": [r for r in detected_results if r["category"] == "suspicious"],
                "source_url": f"https://www.virustotal.com/gui/{ioc_type}/{ioc_value}",
            }

            # IOC-specific attributes
            if ioc_type == "ip":
                enriched.update({
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn"),
                    "as_owner": attributes.get("as_owner"),
                    "reputation": attributes.get("reputation", 0),
                })
            elif ioc_type == "domain":
                enriched.update({
                    "creation_date": attributes.get("creation_date"),
                    "registrar": attributes.get("registrar"),
                    "last_dns_records": attributes.get("last_dns_records", [])[:5],
                })
            elif ioc_type == "hash":
                enriched.update({
                    "file_type": attributes.get("type_description"),
                    "file_names": attributes.get("names", [])[:5],
                    "file_size": attributes.get("size"),
                    "first_submission": attributes.get("first_submission_date"),
                    "last_submission": attributes.get("last_submission_date"),
                    "tags": attributes.get("tags", []),
                    "signature": attributes.get("signature_info", {}),
                })
            elif ioc_type == "url":
                enriched.update({
                    "url": attributes.get("url"),
                    "domain": attributes.get("domain"),
                    "first_submission": attributes.get("first_submission_date"),
                    "last_final_url": attributes.get("last_final_url"),
                })

            return self.result_success(enriched, time.time() - start)

        except Exception as e:
            return self.result_error(str(e), time.time() - start)