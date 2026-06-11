"""
Scoring Engine — weighted risk scoring for enriched IOCs.

Demonstrates:
- Product Thinking (translating raw data into actionable confidence scores)
- Evaluation & Observability (transparent, traceable scoring breakdown)
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ScoringEngine:
    """
    Compute a weighted risk score (0–10) for an IOC based on enrichment data
    from multiple tools.

    Scoring factors (configurable weights):
    - Malicious detection ratio (from VirusTotal)
    - Abuse report volume (from AbuseIPDB)
    - Source coverage (how many tools returned data)
    - Geolocation risk (high-risk country flag)
    - Freshness (recent activity)
    """

    DEFAULT_WEIGHTS = {
        "malicious_reports": 0.35,
        "source_count": 0.20,
        "abuse_reports": 0.25,
        "geo_risk": 0.10,
        "freshness": 0.10,
    }

    HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP", "SY", "VE", "CU", "AF"}

    def __init__(self, weights: Optional[dict] = None, enabled: bool = True):
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        self.enabled = enabled
        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}

    def score(self, enrichment_results: dict[str, dict], ioc_type: str = "ip") -> dict:
        """
        Compute a risk score for an IOC based on all enrichment results.

        Returns:
        {
            "score": float (0-10),
            "severity": str (none/low/medium/high/critical),
            "confidence": float (0-1),
            "factors": { ... breakdown of each factor ... },
            "summary": str (plain-text explanation)
        }
        """
        if not self.enabled:
            return {"score": 0, "severity": "none", "confidence": 0, "factors": {}, "summary": "Scoring disabled"}

        factors = {}
        total_score = 0.0

        # Factor 1: Malicious reports from VirusTotal
        vt_result = enrichment_results.get("virustotal", {})
        malicious_factor = self._score_malicious_reports(vt_result)
        factors["malicious_reports"] = {
            "raw": malicious_factor["raw"],
            "score": malicious_factor["normalized"],
            "weight": self.weights["malicious_reports"],
            "contribution": malicious_factor["normalized"] * self.weights["malicious_reports"] * 10,
            "detail": malicious_factor.get("detail", ""),
        }
        total_score += factors["malicious_reports"]["contribution"]

        # Factor 2: Abuse reports from AbuseIPDB
        abuse_result = enrichment_results.get("abuseipdb", {})
        abuse_factor = self._score_abuse_reports(abuse_result)
        factors["abuse_reports"] = {
            "raw": abuse_factor["raw"],
            "score": abuse_factor["normalized"],
            "weight": self.weights["abuse_reports"],
            "contribution": abuse_factor["normalized"] * self.weights["abuse_reports"] * 10,
            "detail": abuse_factor.get("detail", ""),
        }
        total_score += factors["abuse_reports"]["contribution"]

        # Factor 3: Source coverage (how many tools returned useful data)
        source_factor = self._score_source_coverage(enrichment_results)
        factors["source_coverage"] = {
            "raw": source_factor["raw"],
            "score": source_factor["normalized"],
            "weight": self.weights["source_count"],
            "contribution": source_factor["normalized"] * self.weights["source_count"] * 10,
            "detail": source_factor.get("detail", ""),
        }
        total_score += factors["source_coverage"]["contribution"]

        # Factor 4: Geolocation risk
        geo_factor = self._score_geo_risk(enrichment_results)
        factors["geo_risk"] = {
            "raw": geo_factor["raw"],
            "score": geo_factor["normalized"],
            "weight": self.weights["geo_risk"],
            "contribution": geo_factor["normalized"] * self.weights["geo_risk"] * 10,
            "detail": geo_factor.get("detail", ""),
        }
        total_score += factors["geo_risk"]["contribution"]

        # Factor 5: Freshness
        freshness_factor = self._score_freshness(enrichment_results)
        factors["freshness"] = {
            "raw": freshness_factor["raw"],
            "score": freshness_factor["normalized"],
            "weight": self.weights["freshness"],
            "contribution": freshness_factor["normalized"] * self.weights["freshness"] * 10,
            "detail": freshness_factor.get("detail", ""),
        }
        total_score += factors["freshness"]["contribution"]

        # Clamp to 0-10
        total_score = max(0.0, min(10.0, total_score))

        # Severity
        severity = self._classify_severity(total_score)

        # Confidence: how many tools actually contributed data
        contributing = sum(1 for f in factors.values() if f["raw"] > 0)
        total_factors = len(factors)
        confidence = contributing / total_factors if total_factors > 0 else 0

        return {
            "score": round(total_score, 2),
            "severity": severity,
            "confidence": round(confidence, 2),
            "factors": factors,
            "summary": self._generate_summary(total_score, severity, factors),
        }

    def _score_malicious_reports(self, vt_result: dict) -> dict:
        """Score based on VirusTotal detection ratio."""
        if not vt_result.get("success"):
            return {"raw": -1, "normalized": 0.5, "detail": "VirusTotal unavailable — defaulting to neutral"}

        data = vt_result.get("data", {})
        malicious = data.get("malicious_detections", 0)
        total = data.get("total_engines", 0)

        if total == 0:
            return {"raw": 0, "normalized": 0.1, "detail": "No VirusTotal scan data"}

        ratio = malicious / total

        # Normalized 0-1 (0 = clean, 1 = flagged by many engines)
        if ratio >= 0.5:
            normalized = 1.0
        elif ratio >= 0.25:
            normalized = 0.8
        elif ratio >= 0.1:
            normalized = 0.6
        elif malicious > 0:
            normalized = 0.4
        else:
            normalized = 0.1  # Clean or undetected — low risk contribution

        detail = f"{malicious}/{total} engines detected malicious"
        return {"raw": malicious, "normalized": normalized, "detail": detail}

    def _score_abuse_reports(self, abuse_result: dict) -> dict:
        """Score based on AbuseIPDB confidence score."""
        if not abuse_result.get("success"):
            return {"raw": -1, "normalized": 0.5, "detail": "AbuseIPDB unavailable — defaulting to neutral"}

        data = abuse_result.get("data", {})
        confidence = data.get("abuse_confidence_score", 0)

        # Normalized 0-1 based on confidence score
        normalized = confidence / 100.0

        detail = f"Abuse confidence score: {confidence}/100 ({data.get('total_reports', 0)} reports)"
        return {"raw": confidence, "normalized": normalized, "detail": detail}

    def _score_source_coverage(self, results: dict) -> dict:
        """Score based on how many tools returned successful data."""
        successful = sum(1 for r in results.values() if r.get("success"))
        total = len(results)
        ratio = successful / total if total > 0 else 0

        # More source coverage = more confidence in the score (higher is better)
        # But for risk, having multiple sources confirm is what matters
        # We score this neutrally — it's a confidence multiplier, not a risk signal
        detail = f"{successful}/{total} enrichment tools returned data"
        return {"raw": successful, "normalized": ratio, "detail": detail}

    def _score_geo_risk(self, results: dict) -> dict:
        """Score based on geolocation risk."""
        # Check ipinfo for high-risk country
        ipinfo = results.get("ipinfo", {})
        if ipinfo.get("success"):
            data = ipinfo.get("data", {})
            if data.get("high_risk_country"):
                return {"raw": 1, "normalized": 1.0, "detail": f"High-risk country: {data.get('country', 'Unknown')}"}
            return {"raw": 0, "normalized": 0.0, "detail": f"Country: {data.get('country', 'Unknown')}"}

        # Check AbuseIPDB for country info
        abuse = results.get("abuseipdb", {})
        if abuse.get("success"):
            data = abuse.get("data", {})
            country = data.get("country_code", "")
            if country in self.HIGH_RISK_COUNTRIES:
                return {"raw": 1, "normalized": 1.0, "detail": f"High-risk country: {country}"}
            return {"raw": 0, "normalized": 0.0, "detail": f"Country: {country}"}

        return {"raw": -1, "normalized": 0.3, "detail": "No geolocation data — defaulting to neutral"}

    def _score_freshness(self, results: dict) -> dict:
        """Score based on recency of IOC activity."""
        # AbuseIPDB has last_reported_at
        abuse = results.get("abuseipdb", {})
        if abuse.get("success"):
            data = abuse.get("data", {})
            last_reported = data.get("last_reported_at")
            if last_reported:
                from datetime import datetime
                try:
                    reported = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
                    days_ago = (datetime.now().astimezone() - reported).days
                    if days_ago <= 7:
                        return {"raw": days_ago, "normalized": 1.0, "detail": f"Reported {days_ago} days ago — very recent"}
                    elif days_ago <= 30:
                        return {"raw": days_ago, "normalized": 0.6, "detail": f"Reported {days_ago} days ago — moderately recent"}
                    else:
                        return {"raw": days_ago, "normalized": 0.2, "detail": f"Reported {days_ago} days ago — aged IOC"}
                except Exception:
                    pass

        return {"raw": -1, "normalized": 0.3, "detail": "No freshness data available"}

    def _classify_severity(self, score: float) -> str:
        """Classify a numeric score into severity levels."""
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        return "none"

    @staticmethod
    def _generate_summary(score: float, severity: str, factors: dict) -> str:
        """Generate a plain-text summary of the scoring."""
        parts = [f"Risk score: {score:.1f}/10 ({severity.upper()})"]

        for factor_name, factor_data in factors.items():
            if factor_data["raw"] >= 0:
                parts.append(f"  • {factor_name.replace('_', ' ').title()}: {factor_data['detail']}")

        contributing = sum(1 for f in factors.values() if f["raw"] >= 0)
        parts.append(f"  (Based on {contributing} of {len(factors)} scoring factors)")

        return "\n".join(parts)