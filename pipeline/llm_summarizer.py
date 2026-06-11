"""
LLM Summarizer — optional natural-language threat summary using OpenRouter/OpenAI.

Demonstrates:
- Product Thinking (human-readable summaries for SOC analysts)
- Security & Safety (LLM is a *summarizer*, not a decision-maker)
- Tool & Contract Design (structured prompt with controlled output format)
"""

import json
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class LLMSummarizer:
    """
    Generate a concise natural-language threat summary from enrichment data.

    The LLM is explicitly constrained to:
    - Summarize existing data (not make new judgments)
    - Reference specific numbers and facts from enrichment
    - Keep output short (2-3 sentences)
    - NOT recommend actions (that's the analyst's job)

    This is a *security guardrail* — never let an LLM make security decisions
    autonomously. It describes, it does not decide.
    """

    DEFAULT_PROMPT = (
        "You are a SOC analyst assistant. Given the following IOC enrichment data, "
        "write a concise 2-3 sentence threat summary. Focus on: what kind of threat "
        "this likely represents, how confident you are, and what action you recommend. "
        "Be specific — reference the actual data (report counts, geolocation, etc.)."
    )

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", False)

        # Determine provider and API key
        self.provider = self.config.get("provider", "openrouter")
        self.model = self.config.get("model", "openai/gpt-4o-mini")
        self.max_tokens = self.config.get("max_tokens", 250)
        self.temperature = self.config.get("temperature", 0.3)
        self.prompt_template = self.config.get("prompt_template", self.DEFAULT_PROMPT)

        if self.provider == "openrouter":
            self.api_key = os.getenv("OPENROUTER_API_KEY", "")
            self.api_url = "https://openrouter.ai/api/v1/chat/completions"
            # Check if we should use a direct API key from env
            direct_key = os.getenv("LLM_API_KEY", "")
            if direct_key:
                self.api_key = direct_key
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY", "")
            self.api_url = "https://api.openai.com/v1/chat/completions"
        else:
            # Custom provider — assume OpenAI-compatible endpoint
            self.api_key = os.getenv("LLM_API_KEY", "")
            self.api_url = self.config.get("api_url", "https://openrouter.ai/api/v1/chat/completions")

        if not self.api_key:
            self.enabled = False
            logger.info("LLM Summarizer disabled: no API key found")

    def _build_prompt(self, ioc_type: str, ioc_value: str, results: dict, score_result: Optional[dict] = None) -> str:
        """Build a structured prompt with enrichment data for the LLM."""
        sections = [f"IOC: {ioc_type.upper()} — {ioc_value}", ""]

        if score_result:
            sections.append(f"Risk Score: {score_result.get('score', 'N/A')}/10 ({score_result.get('severity', 'N/A').upper()})")
            sections.append("")

        for tool_name, result in results.items():
            if not result.get("success"):
                continue
            data = result.get("data", {})
            sections.append(f"--- {tool_name.upper()} ---")

            if tool_name == "virustotal":
                sections.append(f"  Malicious detections: {data.get('malicious_detections', 'N/A')} / {data.get('total_engines', 'N/A')} engines")
                if data.get("detected_by"):
                    engines = [d["engine"] for d in data["detected_by"][:5]]
                    sections.append(f"  Detected by: {', '.join(engines)}")
            elif tool_name == "abuseipdb":
                sections.append(f"  Abuse confidence: {data.get('abuse_confidence_score', 'N/A')}/100")
                sections.append(f"  Total reports: {data.get('total_reports', 'N/A')}")
                sections.append(f"  ISP: {data.get('isp', 'N/A')}")
                sections.append(f"  Usage type: {data.get('usage_type', 'N/A')}")
            elif tool_name == "ipinfo":
                sections.append(f"  Location: {data.get('city', 'N/A')}, {data.get('country', 'N/A')}")
                sections.append(f"  ISP: {data.get('isp', 'N/A')}")
                sections.append(f"  ASN: {data.get('asn', 'N/A')}")

            sections.append("")

        # Add scoring factor details
        if score_result and "factors" in score_result:
            sections.append("--- SCORING FACTORS ---")
            for name, factor in score_result["factors"].items():
                sections.append(f"  {name}: {factor.get('detail', 'N/A')} (contribution: {factor.get('contribution', 0):.1f})")
            sections.append("")

        return "\n".join(sections)

    def summarize(self, ioc_type: str, ioc_value: str, results: dict,
                  score_result: Optional[dict] = None) -> Optional[str]:
        """
        Generate a threat summary using the LLM.
        Returns None if LLM is disabled or fails.
        """
        if not self.enabled:
            return None

        import requests as req

        prompt = self._build_prompt(ioc_type, ioc_value, results, score_result)

        try:
            response = req.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/ioc-enrichment-pipeline",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self.prompt_template},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                },
                timeout=30,
            )

            if response.status_code != 200:
                logger.warning(f"LLM API returned HTTP {response.status_code}: {response.text[:200]}")
                return None

            data = response.json()
            summary = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            return summary if summary else None

        except Exception as e:
            logger.warning(f"LLM summarizer failed: {e}")
            return None