"""
Pipeline Orchestrator — ties together parsing, enrichment, caching, scoring, and output.

This is the main entry point for the enrichment pipeline. It coordinates the full flow:
1. Parse input IOCs
2. Check cache for existing results
3. Enrich new IOCs via the EnrichmentManager
4. Store results in cache
5. Compute risk scores
6. Generate optional LLM summaries
7. Format and output results

Demonstrates:
- System Design (orchestration of independent components)
- Reliability Engineering (graceful degradation when components fail)
- Evaluation & Observability (full tracing of each step)
"""

import logging
import time
from typing import Optional

from .ioc_parser import IOC, IOCParser
from .cache import EnrichmentCache
from .tools.manager import EnrichmentManager
from .scoring import ScoringEngine
from .output import OutputFormatter
from .llm_summarizer import LLMSummarizer

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Orchestrates the full IOC enrichment pipeline.
    Each component is independent and swappable.
    """

    def __init__(self, config: dict = None):
        self.config = config or {}

        # Initialize components
        cache_cfg = self.config.get("cache", {})
        self.cache = EnrichmentCache(
            db_path=cache_cfg.get("path", "pipeline_cache.db"),
            default_ttl=cache_cfg.get("default_ttl", 3600),
            ttl_by_type=cache_cfg.get("ttl_by_type", {}),
        )

        enrich_cfg = self.config.get("enrichment", {})
        self.manager = EnrichmentManager(enrich_cfg)

        score_cfg = self.config.get("scoring", {})
        self.scoring = ScoringEngine(
            weights=score_cfg.get("weights"),
            enabled=score_cfg.get("enabled", True),
        )

        output_cfg = self.config.get("output", {})
        self.output = OutputFormatter(output_cfg)

        llm_cfg = self.config.get("llm", {})
        self.llm = LLMSummarizer(llm_cfg)

        self._run_stats = {
            "iocs_processed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "enrichments_done": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

    def _get_cache_results(self, ioc: IOC) -> dict:
        """Get all cached enrichment results for an IOC."""
        return self.cache.get_cache_for_ioc(ioc.type, ioc.value)

    def _enrich_with_cache(self, ioc: IOC) -> tuple[dict, bool]:
        """
        Enrich an IOC, using cache when possible.
        Returns (results dict, bool was_cached).
        """
        # Check cache for each tool
        cached_results = {}
        uncached_tools = []

        for tool_name in self.manager.get_enabled_tool_names():
            cached = self.cache.get(ioc.type, ioc.value, tool_name)
            if cached is not None:
                cached_results[tool_name] = {
                    "tool": tool_name,
                    "success": True,
                    "data": cached,
                    "error": None,
                    "latency": 0,
                    "_cached": True,
                }
            else:
                uncached_tools.append(tool_name)

        if not uncached_tools:
            # Everything was cached
            return cached_results, True

        # Enrich uncached IOCs using all tools (manager handles which ones to run)
        fresh_results = self.manager.enrich_all(ioc.type, ioc.value)

        # Cache the fresh results
        for tool_name, result in fresh_results.items():
            if result.get("success") and result.get("data"):
                self.cache.set(ioc.type, ioc.value, tool_name, result["data"])

        # Merge cached + fresh
        merged = dict(cached_results)
        merged.update(fresh_results)
        return merged, len(cached_results) > 0

    def process_ioc(self, ioc: IOC, use_llm: bool = False, output_format: str = "json") -> dict:
        """
        Process a single IOC through the full pipeline.
        Returns a structured result dict.
        """
        start_time = time.time()
        self._run_stats["start_time"] = self._run_stats["start_time"] or start_time

        logger.info(f"Processing IOC: [{ioc.type}] {ioc.value}")

        # Step 1: Enrich (with cache)
        try:
            results, was_cached = self._enrich_with_cache(ioc)
        except Exception as e:
            logger.error(f"Enrichment failed for {ioc.value}: {e}")
            results = {}
            was_cached = False

        if was_cached:
            self._run_stats["cache_hits"] += 1
        else:
            self._run_stats["cache_misses"] += 1
        self._run_stats["enrichments_done"] += len(results)

        # Step 2: Score
        try:
            score_result = self.scoring.score(results, ioc.type)
        except Exception as e:
            logger.error(f"Scoring failed for {ioc.value}: {e}")
            score_result = {"score": 0, "severity": "error", "confidence": 0, "summary": f"Scoring error: {e}"}

        # Step 3: LLM summary (optional)
        llm_summary = None
        if use_llm:
            try:
                llm_summary = self.llm.summarize(ioc.type, ioc.value, results, score_result)
            except Exception as e:
                logger.warning(f"LLM summary failed: {e}")

        # Step 4: Format output
        try:
            output_content = self._format_output(ioc, results, score_result, llm_summary, output_format)
        except Exception as e:
            logger.error(f"Output formatting failed: {e}")
            output_content = str({"error": f"Output formatting failed: {e}"})

        elapsed = round(time.time() - start_time, 3)
        self._run_stats["iocs_processed"] += 1

        return {
            "ioc": ioc,
            "results": results,
            "score": score_result,
            "llm_summary": llm_summary,
            "output": output_content,
            "output_format": output_format,
            "was_cached": was_cached,
            "elapsed": elapsed,
        }

    def _format_output(self, ioc: IOC, results: dict, score_result: dict,
                       llm_summary: Optional[str], output_format: str) -> str:
        """Format the output according to the requested format."""
        if output_format == "json":
            return self.output.format_json(ioc, results, score_result, llm_summary)
        elif output_format == "splunk":
            return self.output.format_splunk(ioc, results, score_result, llm_summary)
        elif output_format == "table":
            return self.output.format_table(ioc, results, score_result, llm_summary)
        else:
            return self.output.format_json(ioc, results, score_result, llm_summary)

    def process_iocs(self, iocs: list[IOC], use_llm: bool = False,
                     output_format: str = "json") -> list[dict]:
        """Process multiple IOCs through the pipeline."""
        results = []
        for ioc in iocs:
            result = self.process_ioc(ioc, use_llm, output_format)
            results.append(result)
        self._run_stats["end_time"] = time.time()
        return results

    def process_file(self, filepath: str, use_llm: bool = False,
                     output_format: str = "json") -> list[dict]:
        """Parse a file and process all IOCs through the pipeline."""
        iocs = IOCParser.parse_file(filepath)
        logger.info(f"Parsed {len(iocs)} IOCs from {filepath}")
        return self.process_iocs(iocs, use_llm, output_format)

    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        stats = dict(self._run_stats)
        if stats["start_time"] and stats["end_time"]:
            stats["total_time"] = round(stats["end_time"] - stats["start_time"], 3)
        else:
            stats["total_time"] = 0
        stats["enrichment_stats"] = self.manager.get_stats()
        stats["cache_stats"] = self.cache.stats()
        return stats