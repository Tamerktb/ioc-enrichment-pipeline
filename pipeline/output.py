"""
Output Formatter — converts enrichment results into multiple output formats.

Demonstrates:
- Product Thinking (multiple output formats for different consumers: humans, SIEM, APIs)
- Evaluation & Observability (structured, parseable output with trace metadata)
"""

import json
import csv
import io
import os
from datetime import datetime, timezone
from typing import Optional


class OutputFormatter:
    """
    Format enrichment results for different consumers:
    - json: Full structured report (for APIs, storage, further processing)
    - splunk: Key-value pair format (for SIEM ingestion)
    - table: Human-readable Rich terminal table (for CLI users)
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.default_format = self.config.get("default_format", "json")
        self.timestamp_format = self.config.get("timestamp_format", "iso")
        self.output_dir = self.config.get("output_dir", "output/")

    def _timestamp(self) -> str:
        """Get a formatted timestamp."""
        now = datetime.now(timezone.utc)
        if self.timestamp_format == "unix":
            return str(int(now.timestamp()))
        return now.isoformat()

    def format_json(self, ioc: any, results: dict, score_result: Optional[dict] = None,
                    llm_summary: Optional[str] = None) -> str:
        """Format as a full JSON report."""
        report = {
            "report_metadata": {
                "generated_at": self._timestamp(),
                "pipeline_version": "1.0.0",
                "ioc_count": 1,
            },
            "ioc": {
                "type": ioc.type,
                "value": ioc.value,
                "source": ioc.source,
                "context": ioc.context,
            },
            "enrichment": {
                tool_name: {
                    "success": result.get("success", False),
                    "error": result.get("error"),
                    "latency_ms": int(result.get("latency", 0) * 1000) if result.get("latency") else None,
                    "data": result.get("data", {}),
                }
                for tool_name, result in results.items()
            },
        }

        if score_result:
            report["risk_score"] = score_result

        if llm_summary:
            report["llm_threat_summary"] = llm_summary

        return json.dumps(report, indent=2, default=str)

    def format_splunk(self, ioc: any, results: dict, score_result: Optional[dict] = None,
                      llm_summary: Optional[str] = None) -> str:
        """Format as Splunk-compatible key-value pairs (one line per IOC)."""
        timestamp = self._timestamp()

        # Base fields
        fields = {
            "source": "ioc_enrichment_pipeline",
            "sourcetype": "ioc_enrichment",
            "timestamp": timestamp,
            "ioc_type": ioc.type,
            "ioc_value": ioc.value,
            "ioc_source": ioc.source,
        }

        # Add enrichment data as flat key-value pairs
        for tool_name, result in results.items():
            prefix = tool_name
            fields[f"{prefix}_success"] = str(result.get("success", False))
            fields[f"{prefix}_error"] = str(result.get("error", ""))
            fields[f"{prefix}_latency_ms"] = str(int(result.get("latency", 0) * 1000))

            data = result.get("data", {})
            if result.get("success") and data:
                if tool_name == "virustotal":
                    fields[f"{prefix}_malicious"] = str(data.get("malicious_detections", 0))
                    fields[f"{prefix}_total_engines"] = str(data.get("total_engines", 0))
                    fields[f"{prefix}_detection_ratio"] = data.get("detection_ratio", "0/0")
                elif tool_name == "abuseipdb":
                    fields[f"{prefix}_confidence"] = str(data.get("abuse_confidence_score", 0))
                    fields[f"{prefix}_total_reports"] = str(data.get("total_reports", 0))
                    fields[f"{prefix}_severity"] = data.get("severity", "none")
                elif tool_name == "ipinfo":
                    fields[f"{prefix}_country"] = str(data.get("country", ""))
                    fields[f"{prefix}_isp"] = str(data.get("isp", ""))
                    fields[f"{prefix}_asn"] = str(data.get("asn", ""))
                    fields[f"{prefix}_high_risk"] = str(data.get("high_risk_country", False))

        # Add score data
        if score_result:
            fields["risk_score"] = str(score_result.get("score", 0))
            fields["risk_severity"] = score_result.get("severity", "none")
            fields["risk_confidence"] = str(score_result.get("confidence", 0))

        if llm_summary:
            # Splunk fields should not have newlines — truncate or flatten
            fields["llm_summary"] = llm_summary.replace("\n", " | ")[:500]

        # Format as Splunk key-value pairs
        kv_pairs = " ".join(f'{k}="{v}"' for k, v in fields.items() if v and v != "None")
        return kv_pairs

    def format_table(self, ioc: any, results: dict, score_result: Optional[dict] = None,
                     llm_summary: Optional[str] = None) -> str:
        """
        Format as a human-readable string table.
        Returns plain text — Rich formatting is handled by the CLI renderer.
        """
        lines = []
        lines.append("=" * 70)
        lines.append(f"IOC ENRICHMENT REPORT — {ioc.type.upper()}: {ioc.value}")
        lines.append(f"Source: {ioc.source}  |  Context: {ioc.context or 'N/A'}")
        lines.append("=" * 70)
        lines.append("")

        # Summary section
        if score_result:
            score = score_result.get("score", 0)
            severity = score_result.get("severity", "none").upper()
            confidence = score_result.get("confidence", 0)
            lines.append(f"RISK SCORE: {score}/10 ({severity})  |  Confidence: {confidence:.0%}")
            lines.append(f"Summary: {score_result.get('summary', 'N/A')}")
            lines.append("")

        # Per-tool results
        for tool_name, result in results.items():
            status = "✓" if result.get("success") else "✗"
            latency = result.get("latency", 0)
            lines.append(f"[{status}] {tool_name.upper()} ({latency:.2f}s)")

            if result.get("success"):
                data = result.get("data", {})
                if tool_name == "virustotal":
                    lines.append(f"   Detections: {data.get('malicious_detections', 0)} malicious / {data.get('total_engines', 0)} engines")
                    lines.append(f"   Detection ratio: {data.get('detection_ratio', 'N/A')}")
                    if data.get("country"):
                        lines.append(f"   Country: {data.get('country')}  ASN: {data.get('asn', 'N/A')}")
                elif tool_name == "abuseipdb":
                    lines.append(f"   Confidence: {data.get('abuse_confidence_score', 0)}/100")
                    lines.append(f"   Reports: {data.get('total_reports', 0)}  Severity: {data.get('severity', 'none')}")
                    if data.get("isp"):
                        lines.append(f"   ISP: {data.get('isp')}  Domain: {data.get('domain', 'N/A')}")
                elif tool_name == "ipinfo":
                    lines.append(f"   Location: {data.get('city', '?')}, {data.get('region', '?')}, {data.get('country', '?')}")
                    lines.append(f"   ISP: {data.get('isp', 'N/A')}  ASN: {data.get('asn', 'N/A')}")
                    lines.append(f"   Coordinates: {data.get('latitude', '?')}, {data.get('longitude', '?')}")
            else:
                lines.append(f"   Error: {result.get('error', 'Unknown error')}")

            lines.append("")

        if llm_summary:
            lines.append("-" * 70)
            lines.append("LLM THREAT SUMMARY:")
            lines.append(llm_summary)
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def save_report(self, filename: str, content: str):
        """Save a report to the output directory."""
        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        return filepath

    def export_batch_csv(self, enriched_iocs: list[dict], filepath: str):
        """Export multiple enriched IOCs to a CSV summary."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        fieldnames = [
            "ioc_type", "ioc_value", "source", "context",
            "risk_score", "risk_severity", "risk_confidence",
            "vt_malicious", "vt_total", "vt_detection_ratio",
            "abuse_confidence", "abuse_reports", "abuse_severity",
            "ip_country", "ip_isp", "ip_asn", "ip_high_risk",
            "llm_summary",
        ]

        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for entry in enriched_iocs:
                ioc = entry.get("ioc", {})
                results = entry.get("results", {})
                score = entry.get("score", {})

                vt = results.get("virustotal", {}).get("data", {})
                abuse = results.get("abuseipdb", {}).get("data", {})
                ipinfo = results.get("ipinfo", {}).get("data", {})

                row = {
                    "ioc_type": ioc.type if hasattr(ioc, 'type') else ioc.get("type", ""),
                    "ioc_value": ioc.value if hasattr(ioc, 'value') else ioc.get("value", ""),
                    "source": ioc.source if hasattr(ioc, 'source') else ioc.get("source", ""),
                    "context": ioc.context if hasattr(ioc, 'context') else ioc.get("context", ""),
                    "risk_score": score.get("score", ""),
                    "risk_severity": score.get("severity", ""),
                    "risk_confidence": score.get("confidence", ""),
                    "vt_malicious": vt.get("malicious_detections", ""),
                    "vt_total": vt.get("total_engines", ""),
                    "vt_detection_ratio": vt.get("detection_ratio", ""),
                    "abuse_confidence": abuse.get("abuse_confidence_score", ""),
                    "abuse_reports": abuse.get("total_reports", ""),
                    "abuse_severity": abuse.get("severity", ""),
                    "ip_country": ipinfo.get("country", ""),
                    "ip_isp": ipinfo.get("isp", ""),
                    "ip_asn": ipinfo.get("asn", ""),
                    "ip_high_risk": ipinfo.get("high_risk_country", ""),
                    "llm_summary": entry.get("llm_summary", ""),
                }
                writer.writerow(row)

        return filepath